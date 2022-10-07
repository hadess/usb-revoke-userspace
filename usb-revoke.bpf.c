/* SPDX-License-Identifier: GPL-2.0 */


#include "vmlinux.h"
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern int usb_revoke_device(int device_fd, int namespace_fd, int uid) __ksym;

struct usb_revoke_args {
	int device_fd;
	int namespace_fd;
	int uid;
	int retval;
};

SEC("syscall")
int usb_revoke_bpf(struct usb_revoke_args *ctx)
{
	pid_t pid;
	int ret = 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Note: Max 3 args to bpf_printk */
	bpf_printk("getting a call from %d about revoking\n", pid);
	bpf_printk("device_fd: %d\n", ctx->device_fd);
	bpf_printk("namespace_fd: %d uid: %d\n",
		   ctx->namespace_fd,
		   ctx->uid);

	if (ctx->device_fd < 0) {
		bpf_printk("device_fd is invalid");
		return -EINVAL;
	}

	ctx->retval = usb_revoke_device(ctx->device_fd, ctx->namespace_fd, ctx->uid);
	bpf_printk("retval from kernel is: %i\n", ctx->retval);

	// <bentiss> hadess: also, please return 0 unless there is a problem in the arguments
	// <bentiss> otherwise you'll have some weird issues in the syscall blocks
	// <bentiss> so basically: if the code executes: return 0, any other return code means that the verifier complained, and not your fault
	return 0;
}
