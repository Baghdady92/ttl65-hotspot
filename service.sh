#!/system/bin/sh
MODDIR=${0%/*}
while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 3; done
nohup /system/bin/sh "$MODDIR/bin/daemon.sh" "$MODDIR" >>"$MODDIR/module.log" 2>&1 </dev/null &
