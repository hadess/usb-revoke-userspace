# logind-hidraw

brain fart about implementing HIDEVIOCREVOKE through BPF

## Getting started

```bash
make
sudo ./logind-hidraw
```

## How does it work

The kernel patch adds a new function `hidraw_is_revoked`. This
function checks whether a specific file descriptor has been revoked.
Ordinarily, this refers to a value in the in-kernel struct. A new ioctl
`HIDIOCREVOKE` provides the ability to revoke a file descriptor - alas, to do
so one needs to have the file descriptor, i.e our process must sit in between
an application and the kernel to be able to `dup()` the fd and pass it up.
This is how systemd-logind currently works.

However, `hidraw_is_revoked` is `__weak` and can be swapped out for one defined by a
BPF program - at which point the return value is defined by the BPF program
and can thus be controlled by the process that uploaded that BPF program.

```
                +--------- kernel -----------+
	        |                +-----------+
[application] ->| /dev/hidraw0   |   BPF     |<-- [logind-hidraw]
                | /dev/hidraw1   | program   |
                |     ...        +-----------+
		+----------------------------+
```
In the current implementation:
- logind-hidraw uploads a BPF program to the kernel. This program has two
  exposed items: `foreground` and the `authorized_files` map. It overrides
  `hidraw_is_revoked()` too.
- An application calls `open("/dev/hidraw")`.
- the BPF program tracks open/close on `/dev/hidraw` devices and stores the
  open entries in the `authorized_files` map.
- **normal data flow between the hidraw device and the application**,
  logind-hidraw is not involved in this data flow.
- logind-hidraw toggles its foreground state and, through the BPF API,
  changes the `foreground` state in the BPF program, followed by setting the
  `revoked` state for each entry in the `authorized_files` map
- **data flow between hidraw device and the application is now interrupted**,
  as `hidraw_is_revoked()` now returns true for those fds

Note that logind-hidraw has no access to the `/dev/hidraw` devices itself and
does not manage the fds either, how the fds are revoked are an implementation
detail of the BPF program.

Also note that unlike the `ioctl(HIDIOCREVOKE)` approach, the application does
not need to go *through* hidraw-logind to open the device.

## Testing

In terminal one, simulate our now logind-capability:
```bash
sudo ./logind-hidraw
```

In terminal two, open an application that reads a hidraw node (SDL game or plain hid-recorder)
```bash
sudo hid-recorder /dev/hidraw2
```

Finally, in terminal three, emulate the fast user switching (i.e. toggle the
foreground state). In this example implementation, this is done by sending
`SIGUSR1` to our program:
```bash
sudo pkill --signal SIGUSR1 logind-hidraw
```

Terminal two (`hid-recorder`) should no longer have access to the hidraw node and close the fd.

Reopening the hidraw node while logind-hidraw is in background mode makes it ignore the newly created fd.
