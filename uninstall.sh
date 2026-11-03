#!/system/bin/sh
MODDIR=${0%/*}
for d in /sys/class/net/rmnet_data*; do
    [ -d "$d" ] || continue
    tc filter del dev "${d##*/}" egress pref 60650 2>/dev/null
done
rm -f /sys/fs/bpf/ttl65ebpf_prog
if [ -f "$MODDIR/old-hw" ]; then
    old=$(cat "$MODDIR/old-hw")
    if [ "$old" = null ]; then settings delete global tether_offload_disabled >/dev/null 2>&1; else settings put global tether_offload_disabled "$old" >/dev/null 2>&1; fi
fi
if [ -f "$MODDIR/old-bpf" ]; then
    old=$(cat "$MODDIR/old-bpf")
    if [ "$old" = null ]; then device_config delete connectivity override_tether_enable_bpf_offload >/dev/null 2>&1; else device_config put connectivity override_tether_enable_bpf_offload "$old" >/dev/null 2>&1; fi
fi
if [ -f "$MODDIR/old-ttl" ]; then
    old=$(cat "$MODDIR/old-ttl")
    case "$old" in ''|*[!0-9]*) ;; *) echo "$old" > /proc/sys/net/ipv4/ip_default_ttl ;; esac
fi
