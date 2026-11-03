# Hotspot TTL 65 (eBPF)

A Magisk module that sets **IPv4 TTL and IPv6 hop limit to 65** on outgoing cellular `rmnet_data*` interfaces. It uses an eBPF traffic-control filter, so it can work on kernels without the `iptables` TTL target (`xt_HL`).

Adapted from **[habib-the-sweet/ttl64-hotspot](https://github.com/habib-the-sweet/ttl64-hotspot)**. The original project supplies the eBPF implementation; this project adapts the target, loading and Magisk integration for the tested Samsung phone.

## Download and install

1. Download `ttl65-hotspot-v1.0.1.zip` from [Releases](https://github.com/Baghdady92/ttl65-hotspot/releases/tag/v1.0.1). Do not install GitHub's automatically generated source ZIP.
2. In Magisk, open **Modules → Install from storage** and select the module ZIP.
3. Reboot, then turn Mobile Hotspot off and back on and reconnect the client device.
4. Check that client internet access works. For packet-level verification, see below.

Root and a working Magisk installation are required. This release bundles an **arm64/AArch64** loader. It requires kernel `CONFIG_BPF_SYSCALL`, `CONFIG_NET_CLS_BPF`, traffic-control `clsact`, permission to load BPF programs, and a `tc` command supporting `object-pinned`. The script targets raw-IP (`ARPHRD_RAWIP=519`) `rmnet_data*` interfaces; other cellular interface names and non-cellular upstreams are not covered.

## Tested

| Item | Result |
| --- | --- |
| Device | Samsung Galaxy S22 Ultra, SM-S908E |
| Android / firmware | Android 15 / S908EXXSCFYI2 |
| Kernel | 5.10.226-android12-9-30958166-abS908EXXSCFYI2 |
| Magisk | 31.0 |
| Kernel TTL target | Disabled; the eBPF approach loaded successfully |
| Deliberately generated TTL 32 packets | Captured on cellular egress at TTL 65 |
| Ping connectivity | Two replies from two requests |
| Outgoing TCP capture | TTL 65 with valid checksums |
| Hotspot client | User confirmed internet access on a second phone |
| Reboot persistence / IPv6 end-to-end | Not yet verified |

This is an experimental release tested on one device. TTL alone does not guarantee hotspot access on every network. It changes the phone's own outgoing traffic as well as forwarded client traffic.

## What it changes

- Loads `/sys/fs/bpf/ttl65ebpf_prog` using bundled official `bpftool`.
- Attaches an egress filter at preference `60650`, handle `65`, without replacing existing filters or root queueing disciplines.
- Checks every 10 seconds for recreated cellular interfaces and reattaches as needed.
- Sets the phone's default IPv4 TTL to 65.
- Disables hardware tethering offload (`tether_offload_disabled=1`) and requests BPF tethering offload be disabled (`connectivity/override_tether_enable_bpf_offload=false`). Android may apply that override only after restarting tethering or rebooting; our live dump still showed BPF offload enabled during testing. Hardware offload was confirmed disabled.

Disabling offload can increase CPU use and reduce battery life or peak throughput. Other TTL, NFQUEUE, VPN-gateway or tethering modules can interact with this module; it does not uninstall or disable them.

## Verify or troubleshoot

Run these on a computer with an authorized ADB connection:

```sh
adb shell "su -c 'cat /data/adb/modules/ttl65ebpf/module.log'"
adb shell "su -c 'tc -s filter show dev rmnet_data7 egress'"
adb shell "su -c 'timeout 10 tcpdump -i rmnet_data7 -Q out -n -vv -c 5 ip'"
```

Replace `rmnet_data7` with the active cellular upstream shown by `ip route` or `dumpsys tethering`. `tcpdump` is optional and is not bundled. Outgoing packets should show `ttl 65`; internet replies keep their normal TTL. The default sysctl alone does **not** verify forwarded hotspot traffic.

If loading fails, read `module.log`; this module does not add missing eBPF kernel support. Do not change SELinux to permissive to make it work.

## Stop and remove

While the module is active, disabling it in Magisk is detected within about 10 seconds. The daemon then removes its filters and restores saved offload/default-TTL settings. To stop it immediately:

```sh
adb shell "su -c 'touch /data/adb/modules/ttl65ebpf/disable; sh /data/adb/modules/ttl65ebpf/uninstall.sh'"
```

Then remove the module in Magisk and reboot. Saved settings live in the module's `old-hw`, `old-bpf` and `old-ttl` files. If you disable and reboot before the running daemon can clean up, run the cleanup script before deleting the module. It leaves existing `clsact` queueing disciplines in place so other Android filters keep working.

## Package it yourself

```sh
python3 -m unittest discover -s tests -v
python3 scripts/package.py
```

Requires Python 3 and internet access. The script downloads SHA256-pinned upstream inputs, reproduces the three-constant BPF patch and writes a Magisk ZIP plus SHA256 file under `dist/`. It does not require a C compiler. The module ZIP includes the corresponding official bpftool/libbpf source archive.

The BPF object was adapted from upstream's **prebuilt** object, not compiled locally. Matching C source is included for inspection and independent compilation; see [BUILD-NOTES.txt](BUILD-NOTES.txt) and [NOTICE.md](NOTICE.md) for provenance and licenses.
