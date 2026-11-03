#!/usr/bin/env python3
"""Package the tested TTL65 adaptation with verified upstream dependencies."""
import hashlib
import io
import pathlib
import struct
import tarfile
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
UPSTREAM = 'c64067f9d158b41b9fae08841da3852264d06faa'
BPF_ORIGINAL_SHA = '9a171f116b33ec32f8ee76766af3ebefc759c12fa86f775a72456e3171f24276'
BPF_PATCHED_SHA = '8b5f011446157397ea0bb653e9c16d72a429bec2114c02551e7325b864bbc43e'
BPFTOOL_ARCHIVE_SHA = '678cc6fdc545f6baf9fc80bbca3ab4cb0efcd3f4d814c6fada00ca0987a4c6b0'
BPFTOOL_SOURCE_SHA = 'fed76b7acb54d810cc3982eb6394726010114977542fd146695887a7d904b60c'
RELEASE = 'https://github.com/libbpf/bpftool/releases/download/v7.8.1/'


def fetch(name, url, digest):
    cache = ROOT / '.cache' / name
    if not cache.is_file():
        cache.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Checksum mismatch: ' + name)
        cache.write_bytes(data)
    data = cache.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Checksum mismatch: ' + name)
    return data


def patch_bpf(data):
    if hashlib.sha256(data).hexdigest() != BPF_ORIGINAL_SHA:
        raise ValueError('Unexpected upstream BPF object')
    patched = bytearray(data)
    # Verified TARGET assignment plus IPv4 and IPv6 equality comparisons.
    # Preserve all ELF metadata, instruction layout and jump destinations.
    for index, expected in [(2, (0xb4, 2, 0, 64)),
                            (14, (0x15, 3, 24, 64)),
                            (31, (0x16, 1, 7, 64))]:
        offset = 64 + index * 8
        if struct.unpack_from('<BBhi', patched, offset) != expected:
            raise ValueError('Unexpected BPF instruction at ' + str(index))
        struct.pack_into('<i', patched, offset + 4, 65)
    if hashlib.sha256(patched).hexdigest() != BPF_PATCHED_SHA:
        raise ValueError('Unexpected patched BPF digest')
    return bytes(patched)


def main():
    original = fetch('ttl64.bpf.o',
                     f'https://raw.githubusercontent.com/habib-the-sweet/ttl64-hotspot/{UPSTREAM}/bin/ttl64.bpf.o',
                     BPF_ORIGINAL_SHA)
    bpf = patch_bpf(original)
    archive = fetch('bpftool-v7.8.1-arm64.tar.gz',
                    RELEASE + 'bpftool-v7.8.1-arm64.tar.gz', BPFTOOL_ARCHIVE_SHA)
    source = fetch('bpftool-libbpf-v7.8.1-sources.tar.gz',
                   RELEASE + 'bpftool-libbpf-v7.8.1-sources.tar.gz', BPFTOOL_SOURCE_SHA)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        member = next(m for m in tar if m.isfile() and m.name == 'bpftool')
        loader = tar.extractfile(member).read()
    if loader[:4] != b'\x7fELF' or struct.unpack_from('<H', loader, 18)[0] != 183:
        raise ValueError('Expected an AArch64 ELF loader')
    props = dict(line.split('=', 1) for line in (ROOT / 'module.prop').read_text().splitlines() if '=' in line)
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    output = dist / ('ttl65-hotspot-v' + props['version'] + '.zip')
    files = ['module.prop', 'service.sh', 'uninstall.sh', 'customize.sh',
             'bin/daemon.sh', 'src/ttl65.bpf.c', 'LICENSE', 'NOTICE.md',
             'README.md', 'BUILD-NOTES.txt']
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
        for name in files:
            zip_file.write(ROOT / name, name)
        zip_file.writestr('bin/ttl65.bpf.o', bpf)
        zip_file.writestr('bin/bpftool', loader)
        zip_file.writestr('third_party/bpftool-libbpf-v7.8.1-sources.tar.gz', source)
        zip_file.write(ROOT / 'scripts/package.py', 'scripts/package.py')
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    (dist / (output.name + '.sha256')).write_text(digest + '  ' + output.name + '\n')
    print(output)
    print('SHA256: ' + digest)


if __name__ == '__main__':
    main()
