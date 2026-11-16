# Windows: detection and enforcement mechanisms

This document specifies every Windows mechanism PortLock uses or may use to observe and
restrict USB devices: exact names, values, privileges, how each change is undone, how it
fails, and where Microsoft documents it. It is the reference for `guard/windows/` (the
read-only backend, implemented) and for the Windows enforcer (a separate component).

Conventions:

- **Tier** is as defined in DESIGN.md section 6, corrected by section 14.14. *Preventive*:
  Windows refuses the device from the first instant. *Reactive*: PortLock acts after the
  device appeared, so there was a window in which it was usable.
- **UNVERIFIED** marks a statement that could not be confirmed in Microsoft's own
  documentation when this was written. It comes from header files, long-standing practice
  or reasoning, and must be tested before anything depends on it.
- Nothing in this document has been run against a real device by PortLock's test suite.
  The read-only parts (sections 1 to 3) are exercised by `tests/hardware/test_win_live.py`
  on a real machine; every enforcement mechanism (sections 4 to 9) is exercised only
  against fakes.

## Summary: what each mechanism really does

| Mechanism | Purpose | Tier | Scope | Needs |
| --- | --- | --- | --- | --- |
| `CM_Register_Notification` | detect arrival/removal | n/a | all devices | nothing |
| SetupAPI / CfgMgr32 queries | enumerate, read properties | n/a | all devices | nothing |
| `IOCTL_STORAGE_GET_DEVICE_NUMBER` | map device to volumes | n/a | disks, volumes | nothing |
| `CM_Disable_DevNode` + `CM_DISABLE_PERSIST` | block one device | reactive | one device node | administrator |
| `CM_Request_Device_EjectW` | safe removal | reactive | one device | interactive or `SeLoadDriverPrivilege` |
| Device Installation Restrictions | default-deny new devices | preventive **only for never-installed devices** | machine | administrator; may need restart |
| Removable Storage Access (`Deny_*`) | class-wide deny read/write/all | standing (not per arrival) | storage class | administrator; may need restart |
| `StorageDevicePolicies\WriteProtect` | class-wide write protection | standing, UNVERIFIED | USB mass storage | administrator |
| `IOCTL_DISK_SET_DISK_ATTRIBUTES` read-only | per-disk read-only | reactive; **does not revoke existing write access** | one disk | administrator |

The two corrections DESIGN.md 14.14 requires, stated once and applied below:

1. **Device Installation Restrictions stop only devices that were never installed on the
   machine.** A device instance that Windows has already installed (any earlier
   connection, including before PortLock was installed) is not stopped by them, unless
   the retroactive option is used, and that option acts on the matching devices present
   when the policy is applied, by class or id, not on each later arrival. Disabling the
   device node with `CM_DISABLE_PERSIST` on every arrival is therefore the **backstop**,
   and it is reactive.
2. **Reactive read-only does not revoke write access that an existing mount already
   has.** Setting a disk read-only after Windows mounted its volumes does not reliably
   stop writes through the file system that is already mounted, nor through handles that
   are already open. Read-only is dependable only as a **standing baseline** from which
   approved devices are released (`baseline_read_only`); see section 10.

---

## 1. Notification (implemented, read-only)

**API.** `CM_Register_Notification(PCM_NOTIFY_FILTER pFilter, PVOID pContext,
PCM_NOTIFY_CALLBACK pCallback, PHCMNOTIFICATION pNotifyContext)` in `cfgmgr32.dll`,
Windows 8 and later. Closed with `CM_Unregister_Notification(HCMNOTIFICATION)`.
<https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_register_notification>

PortLock registers three filters:

| Filter | `FilterType` | Detail | Why |
| --- | --- | --- | --- |
| USB device interface | `CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE` (0) | `GUID_DEVINTERFACE_USB_DEVICE` `{A5DCBF10-6530-11D2-901F-00C04FB951ED}` | every device on a hub port |
| Volume interface | `CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE` (0) | `GUID_DEVINTERFACE_VOLUME` `{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}` | volumes appearing after their device |
| All device instances | `CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE` (2) | `CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES` (2) | devices enumerated but never started (for example refused by an installation policy) and instance removal |

Actions used: `CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL` (0), `...REMOVAL` (1),
`CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED` (7), `...STARTED` (8), `...REMOVED` (9).
<https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/ne-cfgmgr32-cm_notify_action>

**Rules the implementation follows.** Microsoft states that events should be handled
quickly and blocking work moved to another thread, and that registration does not report
what already exists: register first, then enumerate, and a device arriving in between is
reported both ways. PortLock's callback copies the payload into a bounded queue (1024
items) and returns `ERROR_SUCCESS`; a worker thread waits for the burst to end (0.25 s,
at most 2 s), enumerates, and diffs against the previous snapshot. Events are derived from
snapshots, so a lost or duplicated notification causes a late event, never a wrong one; a
re-check every 30 s bounds the delay. `CM_Unregister_Notification` is never called from
inside the callback: Microsoft documents that it "may cause a deadlock" because the call
waits for pending callbacks.
<https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_unregister_notification>

**Contract with the service** (`guard/base.py`): `start` first, `enumerate` second; an
arrival may be both listed and reported, with the same `connection_id`. `RESYNC` asks the
service to enumerate again. The backend reports `RESYNC` when:

- the notification queue overflowed (a notification was dropped);
- the system resumed from sleep: `PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK
  (2), &DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, &HPOWERNOTIFY)` in `powrprof.dll`, Windows 8 and
  later, delivers `PBT_APMRESUMEAUTOMATIC` (0x12) and `PBT_APMRESUMESUSPEND` (0x7);
  `PBT_APMSUSPEND` (0x4) is ignored. Closed with `PowerUnregisterSuspendResumeNotification`.
  <https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerregistersuspendresumenotification>
  As a backstop the worker treats waking 60 s or more after its planned time as a resume
  (this relies on the monotonic clock advancing during sleep: UNVERIFIED for every
  Windows version);
- the first baseline could not be taken at start: monitoring starts anyway, retries every
  5 s, and reports `RESYNC` instead of an arrival for every present device.

**Privilege.** None. **Undo.** `CM_Unregister_Notification` /
`PowerUnregisterSuspendResumeNotification` on stop. **Failure modes.** Function absent
(Windows 7): polling every 2 s, reported by `portlock doctor`. Registration refused: the
USB interface filter is required (otherwise polling); the volume, instance and power
filters are optional and their absence is noted. The older `RegisterDeviceNotification`
(window or service handle) is not used.
<https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerdevicenotificationw>

## 2. Enumeration (implemented, read-only)

**APIs.** `SetupDiGetClassDevsW(NULL, L"USB", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES)`
lists every present device of the USB enumerator, installed or not;
`SetupDiEnumDeviceInfo`, `SetupDiGetDeviceInstanceIdW`; then `CM_Locate_DevNodeW`,
`CM_Get_Parent`, `CM_Get_Child`, `CM_Get_Sibling`, `CM_Get_DevNode_Status`,
`CM_Get_DevNode_PropertyW`.
<https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw>
<https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_devnode_propertyw>

**Identity.** The device instance id `USB\VID_vvvv&PID_pppp\<instance>` carries vendor and
product ids, and the serial number only if the device reports one and Windows marks it
unique (`CM_DEVCAP_UNIQUEID`, 0x10); otherwise the third segment is generated by Windows
and contains `&`. <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-instance-ids>
<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/standard-usb-identifiers>

| `UsbDevice` field | Source |
| --- | --- |
| `vendor_id`, `product_id`, `serial` | instance id |
| `bcd_device` | `REV_rrrr` in `DEVPKEY_Device_HardwareIds` |
| `interfaces`, `device_class` | `USB\Class_cc&SubClass_ss&Prot_pp` in `DEVPKEY_Device_CompatibleIds` of the device and of its `&MI_nn` child nodes (one entry per function, not per interface descriptor) |
| `product` | `DEVPKEY_Device_BusReportedDeviceDesc` (the device's own string); sanitized by the model |
| `manufacturer` | always `None`: `DEVPKEY_Device_Manufacturer` comes from the driver INF, not the device |
| `bus_path` | `DEVPKEY_Device_LocationPaths` (`...#USBROOT(n)#USB(p)#USB(q)`), else `DEVPKEY_Device_Address` chain |
| `removable` | see below |
| `connection_id` | instance id plus `DEVPKEY_Device_LastArrivalDate`, else a backend token |

**`removable` (DESIGN.md 14.3).** `False` (built in) only for a device **directly on a
root-hub port** that Windows reports as not removable (`CM_DEVCAP_REMOVABLE` (0x4) clear
in `DEVPKEY_Device_Capabilities`, and `DEVPKEY_Device_RemovalPolicy` not
`CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL` (2) or `..._SURPRISE_REMOVAL` (3)), and only if
the root hub itself is not reported removable (a controller in a dock). Any device behind
any other hub is reported `True`. Reason: for a root-hub port Windows takes removability
from platform firmware (ACPI `_UPC.PortIsConnectable` and `_PLD.UserVisible`); for a port
of any other hub it takes it from the `DeviceRemovable` bit in **that hub's own
descriptor**, which the hub, a possibly hostile device, supplies.
<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/how-usb-devices-are-assigned-container-ids>
<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-removalpolicy>
Cost: an internal hub on the mainboard makes the devices behind it (often a webcam or
fingerprint reader) report as external.

**`connection_id`.** The instance id survives a re-plug, so it cannot identify a
connection. `DEVPKEY_Device_LastArrivalDate` (`{83DA6326-97A6-4088-9453-A1923F573B29}`,
pid 102, `DEVPROP_TYPE_FILETIME`) records when the device node last arrived; PortLock uses
`<instance id>@<FILETIME>`. That it changes on every arrival and only then is UNVERIFIED
(no Microsoft Learn page for the key was found; it is in `devpkey.h`). Where it is
missing, the backend issues a random token per instance and ends it when the instance is
seen removed (removal notification or a completed enumeration that no longer lists it).
A re-plug whose removal was never observed keeps the old token: that gap exists only
without the arrival time.

**Privilege.** None. **Failure modes.** A node that vanishes while being read is left
out. A property of the wrong type or size is ignored, never trusted. A device whose
volumes cannot be listed is still reported (`backend_data["volumes"] = "unavailable"`).

## 3. Device-to-volume mapping (implemented, read-only)

1. Walk the device's subtree (not into another USB device) for nodes of setup class
   `GUID_DEVCLASS_DISKDRIVE` `{4D36E967-E325-11CE-BFC1-08002BE10318}` or
   `GUID_DEVCLASS_CDROM` `{4D36E965-...}`; list their `GUID_DEVINTERFACE_DISK`
   `{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}` / `GUID_DEVINTERFACE_CDROM` `{53F56308-...}`
   interfaces with `SetupDiGetClassDevsW(..., DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)`.
2. Open each interface with `CreateFileW` and **no access rights** (`dwDesiredAccess = 0`)
   and send `IOCTL_STORAGE_GET_DEVICE_NUMBER` (0x002D1080) for `STORAGE_DEVICE_NUMBER`
   (`DeviceType`, `DeviceNumber`, `PartitionNumber`).
   <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_storage_get_device_number>
3. Enumerate volumes with `FindFirstVolumeW` / `FindNextVolumeW`; ask each volume device
   (`\\?\Volume{GUID}` without the trailing backslash) the same IOCTL, or
   `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` (0x00560000) for a volume spanning disks. Match
   on `(DeviceType, DeviceNumber)`.
   <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew>
   <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents>
4. `GetVolumePathNamesForVolumeNameW` (drive letters, mounted folders),
   `GetVolumeInformationW` (label, serial, `FILE_READ_ONLY_VOLUME` 0x80000, file system),
   `GetDiskFreeSpaceExW` (size), each under `SetThreadErrorMode(SEM_FAILCRITICALERRORS)`
   so an empty card reader raises no dialog.
   <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamesforvolumenamew>
   <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw>

**Privilege.** None. **Side effect.** `GetVolumeInformationW` makes Windows mount the file
system if it is not mounted yet, which reads from the medium (UNVERIFIED as documented
behaviour). **Failure modes.** A locked (BitLocker) or raw volume, or no medium: the
volume is reported with only its path. An MTP/PTP phone exposes no volume at all; its
storage is reached through Windows Portable Devices, so it maps to nothing here, and
`is_storage_like` (imaging) is what brings it into scope.

## 4. Disabling one device

**API.** `CM_Disable_DevNode(DEVINST dnDevInst, ULONG ulFlags)`, `cfgmgr32.dll`. Flags:
`CM_DISABLE_UI_NOT_OK` (no UI on failure) and `CM_DISABLE_PERSIST` (Windows 10 and later:
"disables the device across reboots"; without it the device is enabled again after a
restart). Flag values from `cfgmgr32.h`: `CM_DISABLE_POLITE` 0x0, `CM_DISABLE_ABSOLUTE`
0x1, `CM_DISABLE_HARDWARE` 0x2, `CM_DISABLE_UI_NOT_OK` 0x4, `CM_DISABLE_PERSIST` 0x8
(values UNVERIFIED against Learn, which lists names only).
<https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_disable_devnode>

**Target.** The USB device node itself (`USB\VID_...\...`), located with
`CM_Locate_DevNodeW(instance id, CM_LOCATE_DEVNODE_NORMAL)`. Disabling the device node
removes its whole stack, so every function of a composite device goes with it.

**Tier.** Reactive. The device was usable from enumeration until the call returned. This is
the **backstop** for every arrival, because installation restrictions (section 6) do not
stop a device Windows installed before.

**Privilege.** Administrator (UNVERIFIED as documented; `CR_ACCESS_DENIED` 0x33 otherwise).

**State check and undo.** Before: `CM_Get_DevNode_Status`; disabled means `DN_HAS_PROBLEM`
(0x400) with problem `CM_PROB_DISABLED` (0x16). Journal kind `win_devnode`, target the
instance id, `previous` = `enabled`/`disabled`. Undo: `CM_Enable_DevNode(dnDevInst, 0)`,
only if the node is still disabled (DESIGN.md 14.17).
<https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_enable_devnode>
A disable persisted with `CM_DISABLE_PERSIST` survives the service; `portlock recover`
must re-enable it from the journal.

**Failure modes.** `CR_NOT_DISABLEABLE` (the node lacks `DN_DISABLEABLE` 0x2000; the
backend reports `backend_data["disableable"]`), `CR_REMOVE_VETOED` (an open handle or a
driver refused; the polite default), `CR_NO_SUCH_DEVNODE` (gone), `CR_ACCESS_DENIED`.
Return-code names from `cfgmgr32.h`; which ones each situation produces is UNVERIFIED.

## 5. Eject

**API.** `CM_Request_Device_EjectW(DEVINST dnDevInst, PPNP_VETO_TYPE pVetoType, LPWSTR
pszVetoName, ULONG ulNameLength, ULONG ulFlags)`. Prepares the device for safe removal and
ejects it if it can be ejected. Pass a `MAX_PATH` veto buffer: with `pszVetoName` NULL the
PnP manager shows a message to the user. On failure `*pVetoType` says why
(`PNP_VETO_TYPE`, for example `PNP_VetoOutstandingOpen`) and `pszVetoName` names who.
<https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_request_device_ejectw>
<https://learn.microsoft.com/en-us/windows/win32/api/cfg/ne-cfg-pnp_veto_type>

**Privilege.** A non-interactive caller (a service) or one in a session not attached to the
console needs `SeLoadDriverPrivilege`; a dock device needs `SeUndockPrivilege`.

**Tier.** Reactive. The device stays connected and can re-enumerate (a hostile one can do
so at will; DESIGN.md 14.6 port hold-down). **Undo.** None needed and none possible: the
device returns when it is re-plugged. Not journaled. **Failure modes.** Vetoed by an open
file (the eject is refused and nothing changes; DESIGN.md 14.11 then blocks the device);
`CR_REMOVE_VETOED`. Eject is used for clean removal before a block, never as a block.

## 6. Device Installation Restriction policies

**Location.** `HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions`
(machine policy; `DeviceInstallation.admx`, "System > Device Installation > Device
Installation Restrictions").
<https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceinstallation>
<https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-deviceinstallation>
<https://learn.microsoft.com/en-us/windows/client-management/client-tools/manage-device-installation-with-group-policy>

| Value | Type | Meaning |
| --- | --- | --- |
| `DenyRemovableDevices` | DWORD 1 | prevent installation of removable devices ("removable" as the parent hub driver reports it) |
| `DenyDeviceIDs` + subkey `DenyDeviceIDs` (values `1`, `2`, ... = ids) | DWORD 1 / REG_SZ list | prevent hardware or compatible ids |
| `DenyDeviceClasses` + subkey `DenyDeviceClasses` | DWORD 1 / REG_SZ list | prevent setup classes (`{GUID}`) |
| `DenyInstanceIDs` + subkey `DenyInstanceIDs` | DWORD 1 / REG_SZ list | prevent device instance ids (Windows 10 2004+) |
| `AllowDeviceIDs`, `AllowDeviceClasses`, `AllowInstanceIDs` (+ subkeys) | DWORD 1 / lists | allow lists |
| `AllowDenyLayered` | DWORD 1 | layered evaluation: instance ids > device ids > class > removable, so an `AllowInstanceIDs` entry can release one approved device from `DenyRemovableDevices` |
| `DenyUnspecified` | DWORD 1 | legacy: deny everything not allowed (replaced by `AllowDenyLayered`) |
| `AllowAdminInstall` | DWORD 1 | exempt local administrators. **PortLock must leave this unset.** |
| `ForceReboot` | | seconds before a forced restart to apply a change |

The ADMX names are documented; the subkey-list layout and the `...Retroactive` value names
(`DenyDeviceIDsRetroactive`, `DenyDeviceClassesRetroactive`,
`DenyInstanceIDsRetroactive`) are what the Group Policy editor writes and are UNVERIFIED
against Learn, which documents them only as the `DeviceInstall_*_Deny_Retroactive` policy
elements.

**What they stop.** Installation, that is, Windows selecting and installing a driver for
a device instance. **They stop only devices that were never installed on the machine.** A
device instance Windows installed earlier (same stick with a serial, or a serial-less one
on the same port) keeps its driver and works. "Prevent installation of removable devices"
also stops driver updates for existing removable devices, not their use. The retroactive
option ("also apply to matching devices that are already installed") blocks access to
matching devices already installed when the policy is applied; Microsoft warns it can make
the machine unusable if it matches the boot disk or network. It exists for id and class
rules, not for `DenyRemovableDevices`.

**Tier.** Preventive for a device that was never installed; **no effect** for one that
was. Therefore PortLock's default-deny is: these values **plus** `CM_Disable_DevNode` with
`CM_DISABLE_PERSIST` on every arrival not approved (section 4). A blocked never-installed
device appears with a problem code and no driver; the backend still enumerates and reports
it (instance notifications, `DIGCF_ALLCLASSES`).

**When it applies.** Microsoft: "If no reboot is forced, the device installation
restriction right won't take effect until the system is restarted." In practice new
arrivals are checked against the current values without a restart (UNVERIFIED). Must be
tested per Windows build before PortLock reports this tier as in effect.

**Privilege.** Administrator (write to HKLM policy key). **Undo.** Journal kind
`win_policy_value`, one entry per value (and per list entry), `previous` = absent or old
data; restore only if the current data still equals what PortLock wrote (a Group Policy
refresh may overwrite it, DESIGN.md 14.17). **Failure modes.** Domain Group Policy
overwrites local values at refresh (typically 90 minutes) or conflicts with them;
`AllowAdminInstall` set by a domain policy exempts administrators; HID: denying all
removable devices would also stop a replacement keyboard (DESIGN.md 2), so protected
devices must be allowed by instance id first. Verification: `C:\Windows\INF\setupapi.dev.log`
section "Device Installation Restrictions Policy Check".

## 7. Removable Storage Access policies

**Location.** `HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices` (machine;
the same values under HKCU apply per user). `RemovableStorage.admx`, "System > Removable
Storage Access". <https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-removablestorage>

| Key below `RemovableStorageDevices` | Class | Values (DWORD 1 = deny) |
| --- | --- | --- |
| (the key itself) | all classes | `Deny_All` |
| `{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}` | removable disks | `Deny_Read`, `Deny_Write`, `Deny_Execute` |
| `{53f56308-b6bf-11d0-94f2-00a0c91efb8b}` | CD and DVD | `Deny_Read`, `Deny_Write`, `Deny_Execute` |
| `{53f56311-b6bf-11d0-94f2-00a0c91efb8b}` | floppy | `Deny_Read`, `Deny_Write`, `Deny_Execute` |
| `{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}` | tape | `Deny_Read`, `Deny_Write`, `Deny_Execute` |
| `{6AC27878-A6FA-4155-BA85-F98F491D4F33}` | WPD (phones, cameras, players over MTP/PTP) | `Deny_Read`, `Deny_Write` |
| `Custom\Deny_Read`, `Custom\Deny_Write` | listed class GUIDs | `Deny_Read`, `Deny_Write` |
| (the key itself) | | `RebootTimeinSeconds_state` + time: force a restart to apply |

A second WPD class GUID, `{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}`, is commonly configured
alongside the first: UNVERIFIED (not found on the CSP page).

**What they do.** Deny read, write or execute access to every device of the class. They are
**class-wide**: there is no per-device exception in these values. Releasing one approved
device means removing the value for the whole class.

**When it applies.** Microsoft: "If no reboot is forced, the access right doesn't take
effect until the operating system is restarted." That makes these values a **standing
baseline**, set in advance, not a per-arrival reaction. Whether a newly arriving device is
covered without a restart once the value has been in effect is UNVERIFIED.

**Tier.** Standing; preventive for devices arriving after the policy took effect. Not
reactive. **Privilege.** Administrator. **Undo.** `win_policy_value` journal entries, same
rule as section 6. **Failure modes.** Overwritten by domain policy; a restart may be
needed; MTP devices are covered only through the WPD key, not the disk key; BitLocker's
"Deny write access to removable drives not protected by BitLocker" is a separate policy
that may also be in force.

## 8. Write protection (`StorageDevicePolicies`)

`HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`, value `WriteProtect`
(DWORD 1): USB mass-storage devices mounted afterwards are write-protected by the storage
stack. **UNVERIFIED in full**: no current Microsoft Learn page documents this value;
whether it applies to UASP devices, to already-mounted volumes, or without re-plugging is
unknown. It is class-wide and standing, like section 7. PortLock must not rely on it
without per-build testing and must prefer section 7. **Undo** would be a
`win_policy_value` journal entry (the target is outside `Software\Policies`, so the
enforcer's fixed list of journal targets would have to include it explicitly).

## 9. Per-disk read-only attribute

**API.** `DeviceIoControl(hDisk, IOCTL_DISK_SET_DISK_ATTRIBUTES, &SET_DISK_ATTRIBUTES, ...)`
on `\\.\PhysicalDriveN` (N from section 3). `SET_DISK_ATTRIBUTES { DWORD Version =
sizeof(SET_DISK_ATTRIBUTES); BOOLEAN Persist; BYTE Reserved1[3]; DWORDLONG Attributes;
DWORDLONG AttributesMask; DWORD Reserved2[4]; }`, `DISK_ATTRIBUTE_READ_ONLY` = 0x2 in both
`Attributes` and `AttributesMask`. `Persist = TRUE` keeps it across restarts. Read back
with `IOCTL_DISK_GET_DISK_ATTRIBUTES`. Windows 7 and later. (Learn says to set `Version` to
`sizeof(GET_DISK_ATTRIBUTES)`; the two structures differ in size, so which one Windows
checks is UNVERIFIED.) The control code is
`CTL_CODE(IOCTL_DISK_BASE, 0x3D, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)` =
0x0007C0F4 (from `winioctl.h`; UNVERIFIED against Learn).
<https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_set_disk_attributes>
<https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-set_disk_attributes>
<https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_disk_attributes>

**Tier.** Reactive, and **it does not revoke write access an existing mount already has**:
file systems mounted before the attribute was set, and handles opened for writing before
it, are not reliably affected until the volume is dismounted and mounted again
(UNVERIFIED in detail; DESIGN.md 14.14 adopts the conservative reading). Using it
dependably requires setting it before any volume of the disk mounts, which a reactive
agent cannot guarantee against automount.

**Privilege.** Administrator; the handle needs read and write access (UNVERIFIED as
documented). **Undo.** Clear the bit the same way, only if it is still set. There is no
`JournalKind` for this attribute in `guard/base.py` today; the enforcer cannot journal it
until one is added (ARCHITECTURE.md calls it `diskattr`). **Failure modes.** Access denied;
the disk disappears; a hostile device ignores the read-only state it is told about (the
attribute is enforced by Windows' disk stack, so an honest controller is not needed, but
data already cached for writing may still be flushed: UNVERIFIED).

## 10. Recommendations

| PortLock function | Mechanism to use | Tier to report | Notes |
| --- | --- | --- | --- |
| Detect | `CM_Register_Notification` (USB interface, volume interface, all instances) + snapshot diff; `PowerRegisterSuspendResumeNotification` | n/a | polling every 2 s where unavailable |
| Block one device | `CM_Disable_DevNode(CM_DISABLE_PERSIST \| CM_DISABLE_UI_NOT_OK)` on the USB device node | reactive | journal `win_devnode`; undo `CM_Enable_DevNode` |
| Default-deny new devices | `DenyRemovableDevices` + `AllowDenyLayered` + `AllowInstanceIDs` for protected and approved devices, **and** devnode disable on every unapproved arrival | preventive only for never-installed devices; reactive otherwise | never set `AllowAdminInstall`; never retroactive by class (could hit the boot disk) |
| Lockdown (storage) | Removable Storage Access `Deny_Read` + `Deny_Write` on the disk, CD/DVD and WPD keys, **and** devnode disable of every storage-like device present and arriving | standing + reactive | restart caveat; journal each value |
| `baseline_read_only` (standing) | Removable Storage Access `Deny_Write` on `{53f5630d-...}` and the WPD key, set in advance | standing | class-wide: approved devices can be released only by lifting the value for the whole class, so per-device release is **not available** with native mechanisms; `StorageDevicePolicies\WriteProtect` is a possible equivalent (UNVERIFIED) |
| Read-only for one device (reactive) | `IOCTL_DISK_SET_DISK_ATTRIBUTES` read-only, then eject or block if writes must stop | reactive, **not dependable** | does not revoke existing write access; report as best effort |
| Eject | `CM_Request_Device_EjectW` with a veto buffer | reactive | for clean removal before a block, never as the block |

Mechanisms that would serve a **standing read-only baseline** on Windows, in order of
preference: (1) Removable Storage Access `Deny_Write` for removable disks and WPD,
documented, class-wide; (2) `StorageDevicePolicies\WriteProtect`, undocumented
(UNVERIFIED), class-wide; (3) the per-disk read-only attribute only if it could be applied
before automount, which PortLock cannot guarantee and therefore does not claim. Native
Windows offers no per-device release from a class-wide write deny; products that provide
one (for example Microsoft Defender for Endpoint device control) are outside PortLock's
standard-library scope and are not used.
