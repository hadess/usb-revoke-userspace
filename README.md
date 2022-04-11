# logind-hidraw

brain fart about implementing HIDEVIOCREVOKE through BPF

## Getting started

```bash
make
sudo ./logind-hidraw
```

Note that old version of `bpftool` might not work, so I'm running the following:
```bash
BPFTOOL=${PATH_TO_COMPILED_KERNEL}/tools/bpf/bpftool/bpftool make
```

## testing

In a terminal:
```bash
sudo ./logind-hidraw
```

This simulates our new logind capability.

In an other terminal, open an application that reads an hidraw node (SDL game or plain hid-recorder)
```bash
sudo hid-recorder /dev/hidraw2
```

Last, in a third terminal, "emulate" the fast user switching by sending `SIGUSR1` to our program:
```bash
sudo pkill --signal SIGUSR1 logind-hidraw
```

The second terminal should not have access to the hidraw node and it closes the fd.

Reopening the hidraw node while logind-hidraw is in the background mode makes it ignore the newly created fd.
