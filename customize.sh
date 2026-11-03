SKIPUNZIP=0
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm "$MODPATH/bin/daemon.sh" 0 0 0755
ui_print "Hotspot TTL 65: eBPF on cellular egress"
set_perm "$MODPATH/bin/bpftool" 0 0 0755
