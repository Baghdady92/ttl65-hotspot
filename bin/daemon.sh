#!/system/bin/sh
MODDIR=$1
PIN=/sys/fs/bpf/ttl65ebpf_prog
if [ ! -e "$PIN" ]; then
    "$MODDIR/bin/bpftool" prog load "$MODDIR/bin/ttl65.bpf.o" "$PIN" type classifier || exit 1
fi
if [ ! -f "$MODDIR/old-hw" ] || [ ! -f "$MODDIR/old-bpf" ]; then
    old_hw=$(settings get global tether_offload_disabled 2>/dev/null)
    old_bpf=$(device_config get connectivity override_tether_enable_bpf_offload 2>/dev/null)
    [ -n "$old_hw" ] && [ -n "$old_bpf" ] || exit 1
    echo "$old_hw" > "$MODDIR/old-hw"
    echo "$old_bpf" > "$MODDIR/old-bpf"
fi
if [ ! -f "$MODDIR/old-ttl" ]; then
    cat /proc/sys/net/ipv4/ip_default_ttl > "$MODDIR/old-ttl" || exit 1
fi
# Android's binder shell commands cannot receive Magisk-private log file FDs.
settings put global tether_offload_disabled 1 >/dev/null 2>&1
device_config put connectivity override_tether_enable_bpf_offload false >/dev/null 2>&1
echo 65 > /proc/sys/net/ipv4/ip_default_ttl
while [ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ]; do
    for d in /sys/class/net/rmnet_data*; do
        [ -d "$d" ] || continue
        [ "$(cat "$d/type")" = 519 ] || continue
        iface=${d##*/}
        tc filter show dev "$iface" egress 2>/dev/null | grep -q 'pref 60650' && continue
        tc qdisc show dev "$iface" | grep -q clsact || tc qdisc add dev "$iface" clsact
        tc filter add dev "$iface" egress protocol all pref 60650 handle 65 bpf object-pinned "$PIN" direct-action && echo "Attached TTL65 to $iface"
    done
    sleep 10
done
sh "$MODDIR/uninstall.sh" >/dev/null 2>&1
