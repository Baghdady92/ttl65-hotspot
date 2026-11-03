Experimental Samsung-compatible TTL 65 adaptation of habib-the-sweet/ttl64-hotspot.

- Uses eBPF on cellular rmnet_data interfaces without requiring xt_HL.
- Bundles the official arm64 bpftool loader for Samsung tc builds without ELF loading.
- Includes Magisk startup, interface monitoring, saved settings and cleanup.
- Includes matching adapted BPF source, upstream attribution, dependency source archive and pinned build inputs.

Tested live on SM-S908E / Android 15 / S908EXXSCFYI2 / kernel 5.10.226 / Magisk 31.0. Packet captures showed TTL 65, ping replies succeeded, and a second phone obtained hotspot internet access. Reboot persistence and IPv6 end-to-end are not yet verified. No universal network compatibility claim is made.

Install the attached module ZIP in Magisk, reboot and restart the hotspot. The automatic source archives are not installable module packages. See README for verification, removal and known limits.
