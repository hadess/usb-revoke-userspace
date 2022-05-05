/* SPDX-License-Identifier: GPL-2.0 */


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * work around libbpf: failed to find skeleton map '.rodata.str1.1'
 * for older bpf_helpers.h
 *
 * reason explained at https://lore.kernel.org/bpf/CAEf4BzZXFwBUb=HWxfzfnA-Nq9OKpNXGa=mPqpQs2ABFPdm=uA@mail.gmail.com/
 */
#ifndef BPF_PRINTK_FMT_MOD

#undef bpf_printk

#define bpf_printk(fmt, ...)				\
({							\
	static const char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

#endif /* BPF_PRINTK_FMT_MOD */

struct usb_revoke_args {
	int busnum;
	int devnum;
	unsigned int uid;
	int retval;
};

SEC("syscall")
int usb_revoke(struct usb_revoke_args *ctx)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;

	//FIXME max 3 args to printk
	bpf_printk("getting a call from %d about usbdev 0x%x:0x%x\n",
		   pid,
		   ctx->busnum,
		   ctx->devnum);

	ctx->retval = 0xbeef;

	return 0;
}
