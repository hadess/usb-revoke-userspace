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
#include "logind-hidraw.skel.h"

struct logind_event {
	__u64 key;
	int pid;
};

static bool foreground = true;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

void sig_int(int signo)
{
	stop = 1;
}

void sig_usr(int signo)
{
	foreground = !foreground;
}

static int handle_bpf_event(void *ctx, void *data, size_t data_sz)
{
	const struct logind_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-8d %-8llx\n", ts, e->pid, e->key);

	return 0;
}

int main(int argc, char **argv)
{
	struct logind_hidraw_bpf *skel;
	int err;
	bool prev_state = foreground;
	struct ring_buffer *rb = NULL;

	//libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = logind_hidraw_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = logind_hidraw_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	if (signal(SIGUSR1, sig_usr) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_bpf_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!stop) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (prev_state != foreground) {
			skel->data->foreground = foreground;
			if (!foreground) {
				__u64 key, prev_key = -1;
				__u8 revoked = 1;

				/* revoke all currently held entries in the allowed list */
				while(bpf_map_get_next_key(bpf_map__fd(skel->maps.authorized_files),
							   &prev_key,
							   &key) == 0) {
					bpf_map_update_elem(bpf_map__fd(skel->maps.authorized_files),
							    &key,
							    &revoked,
							    0);
					prev_key = key;
				}
			}

			printf("new state is %s\n", foreground ? "foreground" : "background");

			prev_state = foreground;
		}
	}

cleanup:
	logind_hidraw_bpf__destroy(skel);
	return -err;
}
