// SPDX-License-Identifier: (GPL-2)

#define _GNU_SOURCE 1
#include <fcntl.h>
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

#include <glib.h>
#include <gio/gio.h>

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
	int device_fd;
	int namespace_fd;
	int uid;
	int retval;
};

static int usb_revoke_fd;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int
usb_revoke_bpf(int device_fd, int namespace_fd, int uid)
{
	struct usb_revoke_args args = {
		.device_fd = device_fd,
		.namespace_fd = namespace_fd,
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

static struct usb_revoke_bpf *
init_bpf (void)
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
		return NULL;
	}

	/* Attach tracepoint handler */
	err = usb_revoke_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	usb_revoke_fd = bpf_program__fd(skel->progs.usb_revoke_bpf);
	if (usb_revoke_fd >= 0)
		return skel;

cleanup:
	usb_revoke_bpf__destroy(skel);
	return NULL;
}

static int device_fd = -1;
static int namespace_fd = -1;
static int uid = -1;

static gboolean
parse_device (const char  *option_name,
	      const char  *value,
	      gpointer     user_data,
	      GError     **error)
{
	g_auto(GStrv) elems = NULL;
	int bus_id, device_id;
	g_autofree char *device_path = NULL;

	elems = g_strsplit (value, ":", 2);
	if (!elems || !elems[0] || !elems[1])
		goto parse_error;

	bus_id = g_ascii_strtoll (elems[0], NULL, 10);
	device_id = g_ascii_strtoll (elems[1], NULL, 10);
	if (bus_id > 64 || bus_id <= 0 ||
	    device_id > 128 || bus_id <= 0)
		goto parse_error;

	device_path = g_strdup_printf ("/dev/bus/usb/%03d/%03d",
				       bus_id, device_id);
	device_fd = open (device_path, 0);
	if (device_fd < 0) {
		g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
			     "Could not open '%s'", device_path);
		return FALSE;
	}
	return TRUE;

parse_error:
	g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		     "Could not parse USB device '%s'", value);
	return FALSE;
}

static gboolean
parse_pid (const char  *option_name,
	   const char  *value,
	   gpointer     user_data,
	   GError     **error)
{
	int pid;
	g_autofree char *namespace_path = NULL;

	pid = g_ascii_strtoll (value, NULL, 10);
	if (pid < 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			     "Could not parse PID '%s'", value);
		return FALSE;
	}

	namespace_path = g_strdup_printf ("/proc/%d/ns/user", pid);
	namespace_fd = open (namespace_path, 0);
	if (namespace_fd < 0) {
		g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
			     "Could not open '%s'", namespace_path);
		return FALSE;
	}

	return TRUE;
}

static GOptionEntry entries[] =
{
	 { "device", 'd', 0, G_OPTION_ARG_CALLBACK, parse_device, "USB device in the bus:dev format", "BUSNUM:DEVNUM" },
	 { "uid", 'u', 0, G_OPTION_ARG_INT, &uid, "UID of the user" },
	 { "pid", 'p', 0, G_OPTION_ARG_CALLBACK, parse_pid, "the PID to get the user namespace from" },
	 G_OPTION_ENTRY_NULL
};

int main(int argc, char **argv)
{
	struct usb_revoke_bpf *skel;
	int err;
	GOptionContext *context;
	GError *error = NULL;

	context = g_option_context_new ("- test tree model performance");
	g_option_context_add_main_entries (context, entries, NULL);
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_print ("Option parsing failed: %s\n", error->message);
		return 1;
	}
	if (device_fd <= 0 && uid < 0 && namespace_fd < 0) {
		g_print ("Either a device, UID or namespace needs to be passed to be revoked\n");
		return 1;
	}

	/* Check we have all the arguments we need */
	skel = init_bpf ();
	if (!skel) {
		g_warning ("Could not setup BPF");
		return 1;
	}

	err = usb_revoke_bpf (device_fd, namespace_fd, uid);

	usb_revoke_bpf__destroy(skel);
	return -err;
}
