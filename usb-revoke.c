// SPDX-License-Identifier: (GPL-2)

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "usb-revoke.skel.h"

/* included in libbpf 0.6
 *
 * We could just use DECLARE_LIBBPF_OPTS but LIBBPF_OPTS is shorter
 */
#ifndef LIBBPF_OPTS
#define LIBBPF_OPTS DECLARE_LIBBPF_OPTS
#endif /* LIBBPF_OPTS */

/* require libbpf 0.5 */
#ifndef __LIBBPF_LEGACY_BPF_H
#error libbpf 0.5+ required
#endif /* __LIBBPF_LEGACY_BPF_H */

struct usb_revoke_args {
	int busnum;
	int devnum;
	unsigned int uid;
	int retval;
};

static int usb_revoke_fd;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int
usb_revoke_bpf(int busnum, int devnum, unsigned int uid)
{
	struct usb_revoke_args args = {
		.busnum = busnum,
		.devnum = devnum,
		.uid = uid,
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, tattr,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);
	int err;

	err = bpf_prog_test_run_opts(usb_revoke_fd, &tattr);

	printf("syscall: %d retval: 0x%04x\n", err, args.retval);

	return 0;
}

int main(int argc, char **argv)
{
	struct usb_revoke_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = usb_revoke_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = usb_revoke_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	usb_revoke_fd = bpf_program__fd(skel->progs.usb_revoke_bpf);
	err = usb_revoke_bpf (1, 2, 3);

cleanup:
	usb_revoke_bpf__destroy(skel);
	return -err;
}
