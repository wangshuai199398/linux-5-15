/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NSPROXY_H
#define _LINUX_NSPROXY_H

#include <linux/spinlock.h>
#include <linux/sched.h>

struct mnt_namespace;
struct uts_namespace;
struct ipc_namespace;
struct pid_namespace;
struct cgroup_namespace;
struct fs_struct;

/*
 * 一个用于保存指向各个进程级命名空间（namespace）指针的结构体，包括：
 * 	文件系统（fs）命名空间（即挂载点 mount）
 * 	UTS（主机名和域名）
 * 	网络命名空间
 *	System V IPC 命名空间（进程间通信）
 * 
 * PID 命名空间是个例外 —— 它是通过 task_active_pid_ns 访问的。
 * nsproxy 结构中的 PID 命名空间是子进程将使用的命名空间。
 *
 * count 表示有多少个任务（task）引用了这个 nsproxy。
 * 每个命名空间的引用计数，实际上是有多少个 nsproxy 指向了它，而不是有多少个任务使用它。
 *
 * 当多个任务共享所有命名空间时，它们共享同一个 nsproxy
 * 一旦某个命名空间被 clone 或 unshare（即被单独创建或分离），内核会复制一份新的 nsproxy。
 */
struct nsproxy {
	atomic_t count;
	//主机名和NIS域名的隔离性
	struct uts_namespace *uts_ns;
	//解决信号量、消息队列和共享内存的隔离性
	struct ipc_namespace *ipc_ns;
	//文件系统隔离性
	struct mnt_namespace *mnt_ns;
	//进程号隔离性
	struct pid_namespace *pid_ns_for_children;
	//解决网络相关的设备、路由表、socket等资源的隔离性
	struct net 	     *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};
extern struct nsproxy init_nsproxy;

/*
 * A structure to encompass all bits needed to install
 * a partial or complete new set of namespaces.
 *
 * If a new user namespace is requested cred will
 * point to a modifiable set of credentials. If a pointer
 * to a modifiable set is needed nsset_cred() must be
 * used and tested.
 */
struct nsset {
	unsigned flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
};

static inline struct cred *nsset_cred(struct nsset *set)
{
	if (set->flags & CLONE_NEWUSER)
		return (struct cred *)set->cred;

	return NULL;
}

/*
 * the namespaces access rules are:
 *
 *  1. only current task is allowed to change tsk->nsproxy pointer or
 *     any pointer on the nsproxy itself.  Current must hold the task_lock
 *     when changing tsk->nsproxy.
 *
 *  2. when accessing (i.e. reading) current task's namespaces - no
 *     precautions should be taken - just dereference the pointers
 *
 *  3. the access to other task namespaces is performed like this
 *     task_lock(task);
 *     nsproxy = task->nsproxy;
 *     if (nsproxy != NULL) {
 *             / *
 *               * work with the namespaces here
 *               * e.g. get the reference on one of them
 *               * /
 *     } / *
 *         * NULL task->nsproxy means that this task is
 *         * almost dead (zombie)
 *         * /
 *     task_unlock(task);
 *
 */

int copy_namespaces(unsigned long flags, struct task_struct *tsk);
void exit_task_namespaces(struct task_struct *tsk);
void switch_task_namespaces(struct task_struct *tsk, struct nsproxy *new);
void free_nsproxy(struct nsproxy *ns);
int unshare_nsproxy_namespaces(unsigned long, struct nsproxy **,
	struct cred *, struct fs_struct *);
int __init nsproxy_cache_init(void);

static inline void put_nsproxy(struct nsproxy *ns)
{
	if (atomic_dec_and_test(&ns->count)) {
		free_nsproxy(ns);
	}
}

static inline void get_nsproxy(struct nsproxy *ns)
{
	atomic_inc(&ns->count);
}

#endif
