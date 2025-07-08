/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_RBTREE_TYPES_H
#define _LINUX_RBTREE_TYPES_H

struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
/* The alignment might seem pointless, but allegedly CRIS needs it */

struct rb_root {
	struct rb_node *rb_node;
};

/*
 * 最左侧缓存的红黑树（rbtrees）
 *
 * 我们没有缓存最右侧节点，是基于内存占用与可能受益于 O(1) 时间复杂度的 rb_last() 的用户数量之间的权衡。这样做并不值得，
 * 那些需要这个功能的用户可以自行实现相关逻辑。此外，想要同时缓存左右指针的用户可能会觉得这种设计有些不对称，但这是可以接受的。
 */
struct rb_root_cached {
	//红黑树根节点
	struct rb_root rb_root;
	//最左面的节点
	struct rb_node *rb_leftmost;
};

#define RB_ROOT (struct rb_root) { NULL, }
#define RB_ROOT_CACHED (struct rb_root_cached) { {NULL, }, NULL }

#endif
