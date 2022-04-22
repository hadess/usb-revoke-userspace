/* SPDX-License-Identifier: GPL-2.0 */


/*
 * Note: for the following code to compile, we need HIDRAW to be included
 * in vmlinuz (CONFIG_HIDRAW=y).
 * If HID is compiled as a separate module, we need to use the vmlinux.h
 * which contains the various hid symbols, it can be generated through:
 *
 * $> ./tools/bpf/bpftool/bpftool btf dump \
 *        file /sys/kernel/btf/hidraw format c > samples/bpf/vmlinux.h
 *
 * Once the code is compiled, the fact that HIDRAW is a separate module
 * or not is not an issue, the same binary will run similarily.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct hidraw_list *);
	__type(value, u8);
} authorized_files SEC(".maps");

int foreground = 1;

SEC("fexit/hidraw_open")
int BPF_PROG(hidraw_open, struct inode *inode, struct file *file, int ret)
{
	pid_t pid;
	const __u8 revoked = 0;
	struct hidraw_list *list = file->private_data;

	if (ret)
		return 0;

	/* not in forgeground, don't care */
	if (!foreground)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("fentry open: pid = %d, list = %p", pid, list);

	/* store the id in the allowed list */
	bpf_map_update_elem(&authorized_files, &list, &revoked, BPF_ANY);

	return 0;
}

SEC("fentry/hidraw_release")
int BPF_PROG(hidraw_release, struct inode *inode, struct file *file)
{
	struct hidraw_list *list = file->private_data;
	pid_t pid;

	/* not in forgeground, don't care */
	if (!foreground)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("fentry delete: pid = %d, list = %p", pid, list);

	/* the file has been closed, we can clean up */
	bpf_map_delete_elem(&authorized_files, &list);

	return 0;
}

static int is_revoked(struct hidraw_list *list)
{
	__u8 *revoked;

	/* first check if the file is in our list */
	revoked = bpf_map_lookup_elem(&authorized_files, &list);

	/* not part of our list, abort */
	if (!revoked)
		return 0;

	/* we are not in foreground, the file is revoked */
	if (!foreground)
		return 1;

	/* foreground, let's use the revoked state */
	return *revoked;
}

SEC("fmod_ret/hidraw_is_revoked")
int BPF_PROG(hidraw_bpf_revoked, struct hidraw_list *list)
{
	return is_revoked(list);
}
