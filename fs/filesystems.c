// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/filesystems.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  table of configured filesystems
 */

#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs_parser.h>

/*
 * 文件系统驱动列表的处理
 * 规则:
 *	对列表的添加、移除和扫描都由 自旋锁（spinlock）保护
 *	模块卸载期间，必须调用 unregister_filesystem() 来注销文件系统。
 *	在以下两种情况下，才可以访问列表中元素的字段：
 *		1) 当前持有自旋锁，或者
 *		2) 当前持有该模块的引用（reference）
 *	第二种方式（持有模块引用）可以通过调用 try_module_get() 实现：
 *		如果返回 0，表示无法获取引用，必须跳过该元素；
 *		如果成功（非 0），说明已获得引用。
 *  一旦获得了模块引用，就可以释放自旋锁。
 */

static struct file_system_type *file_systems;
static DEFINE_RWLOCK(file_systems_lock);

/* WARNING: This can be used only if we _already_ own a reference */
struct file_system_type *get_filesystem(struct file_system_type *fs)
{
	__module_get(fs->owner);
	return fs;
}

void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}

static struct file_system_type **find_filesystem(const char *name, unsigned len)
{
	struct file_system_type **p;
	for (p = &file_systems; *p; p = &(*p)->next)
		if (strncmp((*p)->name, name, len) == 0 &&
		    !(*p)->name[len])
			break;
	return p;
}

/**
 *	注册一个新的文件系统
 *	@fs: 文件系统结构体
 *
 *	将传入的文件系统添加到内核已知的文件系统列表中，以供挂载（mount）及其他系统调用使用。
 *  成功时返回 0，失败时返回一个负的错误码（errno code）。
 *
 *	传入的 struct file_system_type 结构体会被链接到内核的内部结构中，在文件系统被注销之前，不能释放该结构体
 *  filesystem_wangs
 */
 
int register_filesystem(struct file_system_type * fs)
{
	int res = 0;
	struct file_system_type ** p;

	if (fs->parameters &&
	    !fs_validate_description(fs->name, fs->parameters))
		return -EINVAL;

	BUG_ON(strchr(fs->name, '.'));
	if (fs->next)
		return -EBUSY;
	pr_info("%s %d: fs->name %s\n", __func__, __LINE__, fs->name);
	write_lock(&file_systems_lock);
	p = find_filesystem(fs->name, strlen(fs->name));
	if (*p)
		res = -EBUSY;
	else
		*p = fs;//把 fs 加入了文件系统链表
	write_unlock(&file_systems_lock);
	return res;
}

EXPORT_SYMBOL(register_filesystem);

/**
 *	unregister_filesystem - unregister a file system
 *	@fs: filesystem to unregister
 *
 *	Remove a file system that was previously successfully registered
 *	with the kernel. An error is returned if the file system is not found.
 *	Zero is returned on a success.
 *	
 *	Once this function has returned the &struct file_system_type structure
 *	may be freed or reused.
 */
 
int unregister_filesystem(struct file_system_type * fs)
{
	struct file_system_type ** tmp;

	write_lock(&file_systems_lock);
	tmp = &file_systems;
	while (*tmp) {
		if (fs == *tmp) {
			*tmp = fs->next;
			fs->next = NULL;
			write_unlock(&file_systems_lock);
			synchronize_rcu();
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&file_systems_lock);

	return -EINVAL;
}

EXPORT_SYMBOL(unregister_filesystem);

#ifdef CONFIG_SYSFS_SYSCALL
static int fs_index(const char __user * __name)
{
	struct file_system_type * tmp;
	struct filename *name;
	int err, index;

	name = getname(__name);
	err = PTR_ERR(name);
	if (IS_ERR(name))
		return err;

	err = -EINVAL;
	read_lock(&file_systems_lock);
	for (tmp=file_systems, index=0 ; tmp ; tmp=tmp->next, index++) {
		if (strcmp(tmp->name, name->name) == 0) {
			err = index;
			break;
		}
	}
	read_unlock(&file_systems_lock);
	putname(name);
	return err;
}

static int fs_name(unsigned int index, char __user * buf)
{
	struct file_system_type * tmp;
	int len, res;

	read_lock(&file_systems_lock);
	for (tmp = file_systems; tmp; tmp = tmp->next, index--)
		if (index <= 0 && try_module_get(tmp->owner))
			break;
	read_unlock(&file_systems_lock);
	if (!tmp)
		return -EINVAL;

	/* OK, we got the reference, so we can safely block */
	len = strlen(tmp->name) + 1;
	res = copy_to_user(buf, tmp->name, len) ? -EFAULT : 0;
	put_filesystem(tmp);
	return res;
}

static int fs_maxindex(void)
{
	struct file_system_type * tmp;
	int index;

	read_lock(&file_systems_lock);
	for (tmp = file_systems, index = 0 ; tmp ; tmp = tmp->next, index++)
		;
	read_unlock(&file_systems_lock);
	return index;
}

/*
 * Whee.. Weird sysv syscall. 
 */
SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
{
	int retval = -EINVAL;

	switch (option) {
		case 1:
			retval = fs_index((const char __user *) arg1);
			break;

		case 2:
			retval = fs_name(arg1, (char __user *) arg2);
			break;

		case 3:
			retval = fs_maxindex();
			break;
	}
	return retval;
}
#endif

int __init list_bdev_fs_names(char *buf, size_t size)
{
	struct file_system_type *p;
	size_t len;
	int count = 0;

	read_lock(&file_systems_lock);
	for (p = file_systems; p; p = p->next) {
		if (!(p->fs_flags & FS_REQUIRES_DEV))
			continue;
		len = strlen(p->name) + 1;
		if (len > size) {
			pr_warn("%s: truncating file system list\n", __func__);
			break;
		}
		memcpy(buf, p->name, len);
		buf += len;
		size -= len;
		count++;
	}
	read_unlock(&file_systems_lock);
	return count;
}

#ifdef CONFIG_PROC_FS
static int filesystems_proc_show(struct seq_file *m, void *v)
{
	struct file_system_type * tmp;

	read_lock(&file_systems_lock);
	tmp = file_systems;
	while (tmp) {
		seq_printf(m, "%s\t%s\n",
			(tmp->fs_flags & FS_REQUIRES_DEV) ? "" : "nodev",
			tmp->name);
		tmp = tmp->next;
	}
	read_unlock(&file_systems_lock);
	return 0;
}

static int __init proc_filesystems_init(void)
{
	proc_create_single("filesystems", 0, NULL, filesystems_proc_show);
	return 0;
}
module_init(proc_filesystems_init);
#endif

static struct file_system_type *__get_fs_type(const char *name, int len)
{
	struct file_system_type *fs;

	read_lock(&file_systems_lock);
	fs = *(find_filesystem(name, len));
	if (fs && !try_module_get(fs->owner))
		fs = NULL;
	read_unlock(&file_systems_lock);
	return fs;
}

struct file_system_type *get_fs_type(const char *name)
{
	struct file_system_type *fs;
	const char *dot = strchr(name, '.');
	int len = dot ? dot - name : strlen(name);

	fs = __get_fs_type(name, len);
	if (!fs && (request_module("fs-%.*s", len, name) == 0)) {
		fs = __get_fs_type(name, len);
		if (!fs)
			pr_warn_once("request_module fs-%.*s succeeded, but still no fs?\n",
				     len, name);
	}

	if (dot && fs && !(fs->fs_flags & FS_HAS_SUBTYPE)) {
		put_filesystem(fs);
		fs = NULL;
	}
	return fs;
}

EXPORT_SYMBOL(get_fs_type);
