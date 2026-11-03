# Attribution and third-party components

The eBPF program is adapted from [habib-the-sweet/ttl64-hotspot](https://github.com/habib-the-sweet/ttl64-hotspot), commit `c64067f9d158b41b9fae08841da3852264d06faa`. The original MIT copyright notice is preserved in `LICENSE`. This adaptation changes the target to 65 and supplies Samsung-compatible loading, Magisk scripts, packaging and documentation. Original eBPF authors deserve credit for the underlying implementation.

The tested eBPF object was **not compiled locally**. Three verified immediate values in the upstream prebuilt object were changed from 64 to 65; all other bytes were preserved. `scripts/package.py` reproduces and checks this transformation. `src/ttl65.bpf.c` contains the matching adapted source. The BPF program retains its upstream `GPL` kernel license declaration.

Release ZIPs bundle the unmodified, official AArch64 `bpftool` v7.8.1 binary from [libbpf/bpftool](https://github.com/libbpf/bpftool/releases/tag/v7.8.1). This separate executable and its linked components retain their upstream licenses; the module's MIT license does not relicense them. The corresponding official bpftool/libbpf source archive, including its upstream license files and build configuration, is included in `third_party/bpftool-libbpf-v7.8.1-sources.tar.gz` inside each module ZIP. Upstream's build workflow describes the static build environment and dependency sources.

All three downloaded build inputs are pinned by SHA256 in `scripts/package.py`. No private keys, device identifiers, account credentials or captured network traffic are distributed.
