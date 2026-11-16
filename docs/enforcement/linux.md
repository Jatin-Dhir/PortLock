# Enforcement on Linux

This document specifies how Linux can be made to refuse or restrict a USB device, what each
mechanism really guarantees, and how PortLock reads the facts it bases decisions on. It is
the Linux half of the enforcement reference that `DESIGN.md` section 6 points to. Where this
document and `DESIGN.md` section 14 disagree, section 14 wins and this document is wrong.

**Status.** The Linux package (`portlock.guard.linux`) currently *observes* only: sysfs
enumeration, the mount table and kernel uevents. No mechanism in this document is
implemented by it yet, and none has been run against a real device by the test suite or by
hand. Everything below about enforcement is specification for the enforcer, with the source
of each claim. Claims that could not be confirmed in primary documentation (kernel
documentation, kernel commits, man pages) are marked **UNVERIFIED** and must be checked on a
test machine before code relies on them.

Paths below use `1-2` for a device on port 2 of bus 1, `1-2:1.0` for its interface 0 in
configuration 1, `usb1` for the root hub of bus 1 and `sdX` for a disk. They are examples,
not values from any real machine.

## 1. Recommendation

| Goal | Mechanism | Tier | Dependable? |
| --- | --- | --- | --- |
| Refuse devices from boot, before PortLock runs | `usbcore.authorized_default=0` (or `2`) on the kernel command line | preventive | Yes. The only preventive setting from boot (DESIGN 14.19). PortLock reports it (`portlock doctor`) but does not edit the boot loader. |
| Refuse new devices while running | write `0` (or `2`) to every `usbN/authorized_default`, and to `/sys/module/usbcore/parameters/authorized_default` for controllers that appear later | preventive for devices that arrive afterwards | Yes, from the moment of the write. Devices already connected are not affected. |
| Block one device | write `0` to its `authorized` | reactive | Yes. The device is unconfigured and every driver released. |
| Block one function of a composite device | write `0` to the interface's `authorized` | reactive | Partly: the rest of the device stays usable, which is the point and the risk. |
| Read-only storage | standing udev rule that sets `BLKROSET` on every USB disk and partition at `add`, before anything can mount it; PortLock releases approved devices from it (`baseline_read_only`) | preventive | Yes, as a baseline only (DESIGN 14.14). |
| Read-only storage, reactively | `BLKROSET` after the device appeared | reactive | **No.** It does not take away write access that an existing mount already has (section 5.2). Used only to tighten a device nobody has mounted yet, never as the guarantee. |
| Eject | `remove` | reactive | Yes, for "stop talking to it now". The port stays disabled until the device is unplugged. |
| Detach a driver only | driver `unbind` | reactive | **No** as a security control: user space can still reach the device through `/dev/bus/usb`, and the next re-plug binds again. Not used by PortLock for blocking. |

Order of preference for blocking: default-deny (preventive) first, `authorized=0` per
device as the reactive backstop, `remove` only for a clean eject.

## 2. Device authorization: `authorized`

| | |
| --- | --- |
| Path | `/sys/bus/usb/devices/<device>/authorized` (a symlink into `/sys/devices/...`) |
| Values | `1` authorized, `0` not authorized |
| Kernel | 2.6.26 (ABI entry dated July 2008) |
| Privilege | write access to the file: root (the file is root-owned). No capability beyond root's file access is needed. |
| Effect of `0` | The device is deauthorized: its drivers are unbound and it is left unconfigured. It stays enumerated, so its sysfs directory, `idVendor`, `idProduct` and the cached `descriptors` remain readable. That is why `sysfs.py` falls back to `descriptors` for a device without interface directories. |
| Undo | write `1`. The kernel configures the device again and drivers probe. Journal kind `SYSFS_AUTHORIZED`, target the device's sysfs path, `previous` `1`. |
| Tier | reactive: the device was configured and usable from enumeration until the write. |

Failure modes:

- **Device gone** (unplugged between decision and write): `ENOENT` or `ENODEV`. The enforcer
  returns `ok=False` and the removal event follows.
- **Wrong target**: a path whose name does not match the device-name grammar of
  `sysfs.py` (`usbN`, `B-P[.P...]`), or that does not resolve below `/sys/devices/`, must be
  refused before any write (DESIGN 14.17).
- **Root hub**: writing `0` to `usbN/authorized` deauthorizes the whole bus, including the
  operator's keyboard if it is on that bus. Hubs are protected (`SafeEnforcer`), and the
  enforcer must refuse root hubs outright.
- **Re-plug**: a new connection is a new device; `authorized` resets to the controller's
  `authorized_default`. Reactive blocking must repeat on every arrival; the port hold-down
  (DESIGN 14.6) limits how often a device can replay the window.
- **Read-only `/sys`** (containers, `ProtectKernelTunables=yes`): `EROFS`. Reported as not
  enforced.

Reference: [USB authorization][k-auth]; ABI `/sys/bus/usb/device/.../authorized` in
[sysfs-bus-usb][k-abi].

## 3. Default-deny: `authorized_default`

### 3.1 Per host controller

| | |
| --- | --- |
| Path | `/sys/bus/usb/devices/usbN/authorized_default`, one per root hub (host controller) |
| Values | `0` new devices are not authorized; `1` new devices are authorized; `2` only devices "connected to internal USB ports" are authorized |
| Kernel | `0`/`1` since the authorization framework (2.6.26). `2` since 5.1 (commit 7bae0432, "usb: core: add option of only authorizing internal devices"; present in the v5.1-rc4 `Documentation/usb/authorization.txt`). |
| Privilege | root |
| Effect | applies to devices that are enumerated *after* the write. Devices already connected keep their `authorized` value. Root hubs themselves are always authorized. |
| Undo | write back the previous value. Journal kind `SYSFS_AUTHORIZED_DEFAULT`, target the root hub's sysfs path. `restore` writes it back only if the current value still equals what PortLock applied (DESIGN 14.17). |
| Tier | preventive for later arrivals: a device that arrives afterwards is never configured until PortLock authorizes it. |

What value `2` trusts: the kernel decides "internal" by checking whether the `connect_type`
of the port the device is plugged into is `hardwired`, on whatever hub that port belongs
to. PortLock's own definition of built in is stricter (section 7): only a root-hub port
counts. Whether an external hub's port can ever report `hardwired` (it is normally `unknown`
there, because the value comes from ACPI) is **UNVERIFIED**; PortLock does not rely on value
`2` for anything behind a hub.

Failure modes:

- **Controllers that appear later** (a Thunderbolt or USB4 dock with its own xHCI, an
  ExpressCard, a USB/IP virtual controller, a controller whose driver loads late) get the
  module-wide default, not the value written to the existing root hubs. See 3.3.
- **Operator lock-out**: with `0`, a USB keyboard plugged in afterwards (or re-plugged) is
  not authorized. Enrolled input devices are authorized by PortLock on arrival; engaging
  default-deny goes through commit-confirm (DESIGN 14.15) and arms the dead-man timer
  outside the process (DESIGN 14.16).
- **Resume from suspend**: devices that the kernel re-enumerates after a failed resume are
  new devices and fall under the default. **UNVERIFIED** in which cases a resume
  re-enumerates rather than resets the device; the backend reports a `RESYNC` when it may
  have missed events, and the pipeline re-applies decisions.

### 3.2 Kernel command line: the only preventive setting from boot

`usbcore.authorized_default=` on the kernel command line, documented in
[kernel-parameters][k-params] as: default `-1` = authorized (same as `1`), `0` = not
authorized, `1` = authorized, `2` = authorized if the device is connected to an internal
port.

With `0` (or `2`), every host controller starts in default-deny as it registers, so no
device is configured before PortLock runs (DESIGN 14.19). Writing `authorized_default` at
service start is reactive with respect to boot: everything enumerated between controller
initialisation and the service starting was authorized by the kernel.

- **Who sets it**: the administrator, in the boot loader configuration. PortLock never
  edits the boot loader; `portlock doctor` reads `/proc/cmdline` and reports whether the
  parameter is present and with which value.
- **Risk**: with `0`, a USB keyboard is unusable at the boot loader's handover, in the
  initramfs (disk-encryption passphrase prompt) and on the console until something
  authorizes it. Value `2` keeps hardwired internal devices working. The administrator must
  have another way in (a non-USB keyboard, a serial console, remote access) before setting
  `0`.
- **Undo**: remove the parameter and reboot; or, at runtime, write `1` to each
  `authorized_default` and to the module parameter (3.3).

### 3.3 Controllers that appear later

`/sys/module/usbcore/parameters/authorized_default` holds the module-wide default that a
host controller receives when it registers. Writing `0` there makes controllers registered
afterwards start in default-deny; writing to `usbN/authorized_default` covers only the
controllers that exist at the time. PortLock's default-deny therefore writes both, and
journals both.

The parameter being writable at runtime by root (mode `0644`) and being read at controller
registration are taken from the kernel source (`drivers/usb/core/hcd.c`), not from
documentation: **UNVERIFIED**. If it turns out read-only on a given kernel, a controller that
appears later must be caught by its `add` uevent (subsystem `usb`, a new `usbN`) and have
its `authorized_default` written reactively; devices that enumerate on it before that write
are a reactive window, and `portlock doctor` says so.

## 4. Interface authorization

| | |
| --- | --- |
| Paths | `/sys/bus/usb/devices/<interface>/authorized` (e.g. `1-2:1.0`); default per bus in `/sys/bus/usb/devices/usbN/interface_authorized_default` |
| Values | `1` / `0`; `interface_authorized_default` is `1` by default |
| Kernel | ABI entries dated August 2015; kernel 4.4 (**UNVERIFIED**: version inferred from the date) |
| Privilege | root |
| Effect | "A deauthorized interface cannot be probed or claimed." The other interfaces of the device keep working. |
| Undo | write `1`, then write the interface name to `/sys/bus/usb/drivers_probe`; the kernel does not probe a re-authorized interface by itself. Drivers that need several interfaces need all of them authorized first. |
| Tier | reactive, or preventive per bus with `interface_authorized_default=0` |

Use: removing the storage function of a composite device while leaving, say, its audio.
DESIGN 2 and 14.2 make a device that mixes input with anything else a policy matter whose
default is deny, so PortLock blocks such a device whole (`authorized=0`) and does not try to
leave its input interface working. Interface authorization is reserved for policies that
explicitly allow a subset of functions. There is no `JournalKind` for it yet; adding the
mechanism requires one.

Reference: [USB authorization][k-auth], [sysfs-bus-usb][k-abi].

## 5. Read-only storage

### 5.1 `BLKROSET`

| | |
| --- | --- |
| Interface | `ioctl(fd, BLKROSET, &one)` on the block device node (`/dev/sdX`, `/dev/sdXN`); `BLKROGET` reads it. `blockdev --setro` / `--setrw` is the command-line form (PortLock calls the ioctl through its `SysfsIO`/`CommandRunner` seams, never `blockdev` in tests). |
| Visible as | `/sys/class/block/<name>/ro` (`1` read-only). `sysfs.py` reports it as `Volume.read_only`. |
| Privilege | `CAP_SYS_ADMIN` (from `block/ioctl.c`; **UNVERIFIED** against documentation), plus permission to open the node. |
| Undo | `BLKROSET` with `0`. Journal kind `BLOCK_READ_ONLY`, target the device node. |
| Disk vs partitions | PortLock sets the disk *and* every partition. Whether the disk's flag alone makes its partitions read-only depends on the kernel version (**UNVERIFIED**), so it does not rely on it. |

### 5.2 What reactive read-only does not do (DESIGN 14.14)

Setting the read-only flag does **not** revoke write access that already exists:

- A filesystem mounted read-write before the flag was set keeps writing. Since kernel 4.18
  the block layer lets a write to a read-only device proceed and only logs "Trying to write
  to read-only block-device" (commit a32e236e, "Partially revert 'block: fail op_is_write()
  requests to read-only partitions'", which turned the earlier failure into a warning; later
  kernels rate-limit and then warn once per partition). The flag therefore does not stop the
  page cache of an existing read-write mount from being written back.
- A file descriptor opened for writing before the flag was set is not closed. New opens for
  writing are refused (**UNVERIFIED**: from `blkdev_open` in the kernel source).
- New `mount` calls on a read-only device fail for read-write or fall back to read-only,
  depending on the filesystem and options.

Consequently reactive read-only is dependable only if it wins the race against every
mounter, which it cannot guarantee. **Read-only is dependable only as a standing baseline**:
a udev rule makes every USB disk and partition read-only at `add`, before any mounter sees
it, and PortLock *releases* a device it has approved (`baseline_read_only`). Revoking a
device that already has a read-write mount follows DESIGN 14.11 instead: switch to
read-only, attempt a clean unmount and eject with a short timeout, then block.

### 5.3 The udev ordering that makes the baseline work

The rule file, written by the enforcer as `/etc/udev/rules.d/60-portlock-readonly.rules`
(journal kind `UDEV_RULE`, target the file path, `previous` `None` so restore deletes it):

```
# PortLock: USB disks and partitions start read-only; PortLock releases approved ones.
ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", \
  ENV{DEVTYPE}=="disk|partition", RUN+="/usr/sbin/blockdev --setro $devnode"
```

Why it works, and what it depends on:

1. **`RUN` runs after all rules for the event** (udev(7): "executed after processing of all
   the rules for the event"; only "very short-running foreground tasks"; long work blocks
   the device's further events).
2. **Listeners see the event after `RUN` has finished.** udisks2 and desktop automounters
   learn about a new block device from the udev monitor, which `systemd-udevd` sends once
   the event, including its `RUN` programs, has been processed. udev(7) does not state this
   ordering; it is taken from `systemd-udevd`'s implementation (**UNVERIFIED** in
   documentation). The rule is what closes the race; PortLock's own reactive `BLKROSET` is
   a second line only.
3. **`ID_BUS`** comes from the `60-persistent-storage.rules` import of the `ata_id` /
   `scsi_id` / `usb_id` builtins. Rules files are processed in lexical order across
   `/usr/lib/udev/rules.d`, `/run/udev/rules.d` and `/etc/udev/rules.d` (a file in `/etc`
   replaces one of the same name elsewhere). A file named `60-portlock-...` sorts after
   `60-persistent-storage.rules`, so `ID_BUS` is set when it is evaluated. A distribution
   that names the storage rules differently needs the file renamed (**UNVERIFIED** per
   distribution).
4. **`change` events** (media inserted in a card reader, partition table re-read) re-apply
   the flag, because a new medium or a re-scanned partition is a new block device state.
5. **After writing the rule**, udev must re-read its rules (`udevadm control --reload`) for
   devices that arrive later; devices already present are not changed by that. The enforcer
   runs this through its `CommandRunner` seam; tests use a fake. Restore deletes the file
   and reloads.
6. **Release**: when a device is approved read-write, PortLock clears the flag on its disk
   and partitions (`BLKROSET 0`) and journals it. A re-plug comes back read-only.

### 5.4 udisks2

udisks2 does not decide on its own to mount; desktop components (for example a session's
volume monitor) call its `Filesystem.Mount()` method, subject to polkit. Relevant controls,
from udisks(8):

- `UDISKS_IGNORE` overrides `HintIgnore` (the device is hidden from user interfaces);
- `UDISKS_AUTO` overrides `HintAuto` (whether it should be automatically started, i.e.
  mounted, by the session);
- `UDISKS_SYSTEM` overrides `HintSystem` (a "system" device needs administrator
  authorization to mount).

PortLock's baseline rule may additionally set `ENV{UDISKS_AUTO}="0"` for devices that are
pending, so the session does not try to mount them at all. A device that udisks2 mounts
while the read-only flag is set gets a read-only mount (or a mount failure). Since udisks2
2.9 (**UNVERIFIED**: version) `/etc/udisks2/mount_options.conf` can force options such as
`ro` per filesystem type; PortLock does not edit it, and it is no substitute for the block
flag, because `mount` run by root ignores it.

## 6. Eject: `remove`

| | |
| --- | --- |
| Path | `/sys/bus/usb/devices/<device>/remove`, write-only (mode `0200`) |
| Value | write `1` |
| Kernel | added by commit 253e0572, "USB: add a 'remove hardware' sysfs attribute" (Alan Stern, 2009; kernel 2.6.33, **UNVERIFIED**: version from the commit date). Not described in the ABI documentation. |
| Effect | the device is deconfigured (as by writing `0` to `bConfigurationValue`) and the hub driver disables its port; per the commit, the port stays disabled until the device is unplugged. |
| Privilege | root |
| Undo | none in software: the user unplugs and re-plugs the device. Not journaled. |
| Failure modes | mounted filesystems lose their device; data not yet written back is lost. PortLock unmounts first (DESIGN 14.11) and audits whether the removal was clean. |

## 7. Built in or external: `removable` and `connect_type` (DESIGN 14.3)

Two kernel attributes describe position:

- `/sys/bus/usb/devices/.../<hub_interface>/port<X>/connect_type`, reached from a device as
  `<device>/port/connect_type`: `hotplug`, `hardwired`, `not used`, or `unknown` when the
  platform does not say ([sysfs-bus-usb][k-abi], January 2013). For a root-hub port the
  value comes from ACPI (`_UPC`/`_PLD`).
- `<device>/removable`: `removable`, `fixed` or `unknown`. The kernel derives it from the
  port's `connect_type` if known, otherwise from the parent hub's descriptor, which a hub
  writes itself (from `set_usb_port_removable()` in `drivers/usb/core/hub.c`;
  **UNVERIFIED** in documentation).

PortLock's rule, implemented in `sysfs.py` (`parse_removable`, `read_usb_devices`):

| Situation | `UsbDevice.removable` |
| --- | --- |
| directly on a root-hub port whose `connect_type` is `hardwired` | `False` (built in) |
| directly on a root-hub port: `hotplug`, or `removable` | `True` |
| directly on a root-hub port: anything else (`fixed` alone, `not used`, `unknown`, missing) | `None` |
| behind any hub whose own answer is `True` | `True` |
| behind any other hub: `hotplug` or `removable` | `True` |
| behind any hub: anything else, *including* `hardwired` and `fixed` | `None`, never `False` |
| a root hub (the host controller itself) | `False` |

A hub describes its own ports: a malicious hub can mark its ports non-removable, and on
platforms where a hub port has firmware data that data still describes a port the user can
reach through the hub. So nothing behind a hub is reported as built in, whatever the hub
says; the unit tests build exactly such a hostile hub. The cost: a genuinely internal device
behind an internal hub (common for laptop cameras and Bluetooth) is `None`, not `False`, and
does not get the built-in protection automatically; the administrator enrols or allows it by
policy. On platforms without ACPI port data (most device-tree systems) `connect_type` is
`unknown` everywhere and nothing is built in.

## 8. Detection, for completeness

- **Uevents**: a `NETLINK_KOBJECT_UEVENT` socket bound to multicast group 1 receives the
  kernel's own events without privilege. `netlink.py` accepts only messages whose sender
  port id is 0 (the kernel) on group 1, which rejects messages from local processes.
- **Lost events**: when the socket's receive buffer overflows the kernel drops messages and
  the next receive fails with `ENOBUFS`; a message larger than the buffer arrives truncated.
  In both cases the backend re-reads sysfs at once and then reports `RESYNC`, after which
  the caller enumerates again (contract in `guard/base.py`).
- **Connection id**: `<boot id>:<busnum>:<devnum>`. `devnum` is assigned anew at every
  enumeration, so a re-plug into the same port (same sysfs path, same `instance_id`) has a
  new connection id; the boot id (`/proc/sys/kernel/random/boot_id`) separates boots. The
  kernel allocates `devnum` round-robin from 1 to 127 per bus, so a value can recur after
  that many enumerations on one bus within one boot. Without a readable boot id the backend
  reports no connection id and says so in its capabilities.
- **Start order**: the backend opens the socket before it reads its baseline, and the caller
  enumerates after `start`, so a device arriving in between is reported both ways rather than
  not at all.

## 9. Containers and WSL

**WSL 2.** The WSL 2 kernel has no USB host controller of its own. USB devices appear only
when attached from Windows over USB/IP (the `usbipd-win` project), as devices on a
`vhci_hcd` virtual controller; until then `/sys/bus/usb/devices` does not exist. The live
read-only test (`tests/hardware/test_linux_live.py`, run on the development machine's WSL
instance) found: boot id readable, uevent socket available, no USB bus, zero USB devices,
37 mount-table entries. Even with a device attached, the device is owned and enumerated by
Windows first; blocking it in WSL only blocks the forwarded copy. **On a WSL machine,
enforcement belongs to the Windows backend**, and the Linux backend's report is
informational. Whether `authorized` on a `vhci_hcd` device behaves as on real hardware is
**UNVERIFIED**.

**Containers.**

- `/sys` is normally mounted read-only inside containers (`EROFS` on every write), and the
  host's devices may or may not be visible. PortLock in a container is a monitor at best;
  `portlock doctor` must report enforcement unavailable.
- Uevents are filtered by network namespace tag; uevents for devices without a tag (USB
  devices) were historically broadcast to all network namespaces, and the "netns: restrict
  uevents" change (commit a3498436b3, 2018) limits that. Exactly which namespaces receive
  USB uevents on a given kernel is **UNVERIFIED**; the backend falls back to polling when
  the socket cannot be opened, but it cannot detect a socket that opens and simply receives
  nothing. Run PortLock in the host's network namespace.
- Since the "netns: send uevent messages" change (2018), a process with `CAP_SYS_ADMIN` in
  the user namespace that owns a network namespace can inject uevents into it. Injected
  messages are delivered by the kernel, so the sender check of section 8 cannot tell them
  apart inside such a namespace. The backend never trusts uevent content (it re-reads
  sysfs), so injection can cause extra reads and `RESYNC`s but not invent a device.
- Mount namespaces: the backend reads `/proc/self/mountinfo`, i.e. its own namespace. A
  service in a private mount namespace sees host mounts only through propagation.

## 10. systemd hardening for the service

The observer needs: read access to `/sys` and `/proc/self/mountinfo`, an `AF_NETLINK`
socket in the host's network namespace, and `AF_UNIX`/`AF_INET` for the local API. The
enforcer additionally needs to write under `/sys/bus/usb` and `/sys/module/usbcore`,
to open block device nodes, `CAP_SYS_ADMIN` for `BLKROSET`, and write access to
`/etc/udev/rules.d`. Options from [systemd.exec(5)][sd-exec] and
[systemd.resource-control(5)][sd-rc]:

| Option | Monitor mode | Enforce mode | Why |
| --- | --- | --- | --- |
| `NoNewPrivileges=yes` (v187) | yes | yes | nothing PortLock runs needs to gain privileges |
| `ProtectSystem=strict` (v214) + `ReadWritePaths=` (v231) | yes, with the state directory writable | yes, plus `/etc/udev/rules.d` | `/dev`, `/proc`, `/sys` are not covered by `strict` |
| `ProtectKernelTunables=yes` (v232) | yes | **no** | makes kernel variables under `/proc/sys` and `/sys` read-only, which includes `authorized` and `authorized_default` |
| `ProtectKernelModules=yes` (v232) | yes | yes | PortLock loads no modules |
| `ProtectControlGroups=yes` (v232) | yes | yes | |
| `PrivateDevices=yes` | yes | **no** | replaces `/dev` with API pseudo devices only and sets `DevicePolicy=closed`: block nodes for `BLKROSET` disappear |
| `DevicePolicy=closed` + `DeviceAllow=block-sd rw` | n/a | yes | limits device node access to SCSI disks (USB storage); **UNVERIFIED** that `block-sd` covers every USB storage path (UAS does) |
| `PrivateNetwork=yes` | **no** | **no** | a new network namespace "will disconnect all socket families from the host, including AF_NETLINK": no kernel uevents |
| `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6` (v211) | yes | yes | |
| `PrivateMounts=yes` (v239) | yes | yes | host mounts propagate in; verify on the target distribution that volume mount points still appear (**UNVERIFIED**) |
| `CapabilityBoundingSet=` | empty (run as an unprivileged user) | `CAP_SYS_ADMIN` (run as root) | sysfs and rules-file writes need only root's ownership of the files; `BLKROSET` needs `CAP_SYS_ADMIN`. That nothing else is needed is **UNVERIFIED** |
| `RestrictNamespaces=yes` (v233), `LockPersonality=yes` (v235), `MemoryDenyWriteExecute=yes` (v231), `SystemCallArchitectures=native` (v209) | yes | yes | |

The dead-man timer (DESIGN 14.16) that runs `portlock recover` is a separate one-shot unit
with the enforce-mode settings, so recovery does not depend on the service.

## 11. Failure modes at a glance

| Failure | Seen as | PortLock reports |
| --- | --- | --- |
| not root, or capability missing | `EACCES` / `EPERM` | `ok=False`, not enforced; capability false in `doctor` |
| `/sys` read-only (container, `ProtectKernelTunables`) | `EROFS` | not enforced |
| device unplugged mid-call | `ENOENT` / `ENODEV` | `ok=False`; the removal event follows |
| kernel without value `2` for `authorized_default` (< 5.1) | **UNVERIFIED**: older kernels may read any non-zero value as "authorized" | the enforcer writes `2` only on 5.1 or later, reads the value back, and reports not enforced if it differs |
| controller registered after default-deny | its root hub at `authorized_default=1` | caught by its `add` uevent and set reactively; reactive window reported |
| uevents dropped | `ENOBUFS` / truncated message | `RESYNC`; re-enumeration |
| uevent socket unavailable | `BackendError` on open | polling, `event_driven=False` with the reason |
| someone else changed a value PortLock set | current value differs from `applied` | `restore` leaves it and audits it (DESIGN 14.17) |
| read-write mount existed before `BLKROSET` | writes continue (kernel warning) | read-only is not claimed; DESIGN 14.11 revocation applies |

## 12. Not verified

Everything marked **UNVERIFIED** above, collected:

1. kernel version of interface authorization (4.4, inferred from the ABI date);
2. `/sys/module/usbcore/parameters/authorized_default` writable at runtime and read at
   controller registration;
3. whether an external hub's port can report `connect_type` `hardwired`;
4. which resume paths re-enumerate devices;
5. `CAP_SYS_ADMIN` for `BLKROSET`; new opens for writing refused on a read-only device;
   whether the disk flag alone covers partitions on a given kernel;
6. that `systemd-udevd` sends an event to monitor listeners only after its `RUN` programs
   finished; the name of the persistent-storage rules file per distribution;
7. the udisks2 version that introduced `mount_options.conf`;
8. the kernel version of the `remove` attribute (2.6.33, from the commit date);
9. how the kernel derives `removable` (from `hub.c`, not documentation);
10. `authorized` on `vhci_hcd` devices in WSL;
11. which network namespaces receive USB uevents after "netns: restrict uevents";
12. `DeviceAllow=block-sd` coverage and mount visibility under `PrivateMounts=yes`;
13. how kernels before 5.1 treat the value `2` written to `authorized_default`;
14. that the enforcer needs no capability other than `CAP_SYS_ADMIN` when run as root.

## References

- [k-auth]: Linux kernel documentation, "Authorizing (or not) your USB devices to connect
  to the system", https://www.kernel.org/doc/html/latest/usb/authorization.html
- [k-abi]: Linux kernel, `Documentation/ABI/testing/sysfs-bus-usb`,
  https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-bus-usb
- [k-params]: Linux kernel, `Documentation/admin-guide/kernel-parameters.txt`, entry
  `usbcore.authorized_default`,
  https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
- Commit 7bae0432 "usb: core: add option of only authorizing internal devices",
  https://lore.kernel.org/lkml/20190222082744.GA6963@kroah.com/
- Commit 253e0572 "USB: add a 'remove hardware' sysfs attribute",
  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=253e05724f9230910344357b1142ad8642ff9f5a
- Commit a32e236e "Partially revert 'block: fail op_is_write() requests to read-only
  partitions'",
  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a32e236eb93e62a0f692e79b7c3c9636689559b9
- "netns: send uevent messages", https://lkml.iu.edu/hypermail/linux/kernel/1803.2/00390.html;
  "netns: restrict uevents", https://lkml.iu.edu/hypermail/linux/kernel/1804.3/03418.html
- [udev(7)](https://man7.org/linux/man-pages/man7/udev.7.html)
- [udisks(8)](https://storaged.org/doc/udisks2-api/latest/udisks.8.html)
- [sd-exec]: systemd.exec(5),
  https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- [sd-rc]: systemd.resource-control(5),
  https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html

[k-auth]: https://www.kernel.org/doc/html/latest/usb/authorization.html
[k-abi]: https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-bus-usb
[k-params]: https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
[sd-exec]: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
[sd-rc]: https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
