import base64
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package', ROOT / 'scripts/package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
ORIGINAL = base64.decodebytes((ROOT / 'third_party/ttl64.bpf.o.base64').read_bytes())


class PackageTests(unittest.TestCase):
    def test_only_three_target_constants_change(self):
        result = package.patch_bpf(ORIGINAL)
        changed = [i for i, pair in enumerate(zip(ORIGINAL, result)) if pair[0] != pair[1]]
        self.assertEqual(changed, [84, 180, 316])
        self.assertTrue(all(ORIGINAL[i] == 64 and result[i] == 65 for i in changed))
        self.assertEqual(hashlib.sha256(result).hexdigest(), package.BPF_PATCHED_SHA)

    def test_unknown_object_rejected(self):
        with self.assertRaises(ValueError):
            package.patch_bpf(ORIGINAL[:-1] + b'X')

    def test_cached_dependency_checked_before_use(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / '.cache').mkdir()
            (root / '.cache/dependency').write_bytes(b'tampered')
            with patch.object(package, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'Checksum mismatch'):
                    package.fetch('dependency', 'https://invalid.invalid/', '0' * 64)

    def test_package_has_sources_loader_and_module_files(self):
        # Small synthetic arm64 ELF tests packaging without downloading dependencies.
        elf = bytearray(64)
        elf[:4] = b'\x7fELF'
        elf[18:20] = (183).to_bytes(2, 'little')
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            member = tarfile.TarInfo('bpftool')
            member.size = len(elf)
            archive.addfile(member, io.BytesIO(elf))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ['module.prop', 'service.sh', 'uninstall.sh', 'customize.sh',
                         'bin/daemon.sh', 'src/ttl65.bpf.c', 'LICENSE', 'NOTICE.md',
                         'README.md', 'BUILD-NOTES.txt', 'scripts/package.py']:
                dst = root / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, dst)
            with patch.object(package, 'ROOT', root), patch.object(package, 'fetch',
                    side_effect=[ORIGINAL, stream.getvalue(), b'upstream-source-archive']):
                package.main()
            output = next((root / 'dist').glob('*.zip'))
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read('bin/ttl65.bpf.o'), package.patch_bpf(ORIGINAL))
                self.assertEqual(archive.read('bin/bpftool'), bytes(elf))
                self.assertEqual(archive.read('third_party/bpftool-libbpf-v7.8.1-sources.tar.gz'),
                                 b'upstream-source-archive')
                self.assertIn('uninstall.sh', archive.namelist())
                self.assertNotIn('module.log', archive.namelist())
            self.assertTrue(Path(str(output) + '.sha256').is_file())

    def test_shell_syntax(self):
        for name in ['service.sh', 'uninstall.sh', 'customize.sh', 'bin/daemon.sh']:
            subprocess.run(['sh', '-n', str(ROOT / name)], check=True)

    def test_cleanup_restores_saved_settings_and_only_own_filter(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copyfile(ROOT / 'uninstall.sh', root / 'uninstall.sh')
            (root / 'old-hw').write_text('null\n')
            (root / 'old-bpf').write_text('true\n')
            mockbin = root / 'mockbin'
            mockbin.mkdir()
            for cmd in ['settings', 'device_config', 'tc', 'rm']:
                script = mockbin / cmd
                script.write_text('#!/bin/sh\necho "' + cmd + ' $*" >> "$TEST_LOG"\n')
                script.chmod(0o755)
            env = dict(os.environ, PATH=str(mockbin) + ':' + os.environ['PATH'],
                       TEST_LOG=str(root / 'calls'))
            subprocess.run(['sh', str(root / 'uninstall.sh')], env=env, check=True)
            calls = (root / 'calls').read_text()
            self.assertIn('settings delete global tether_offload_disabled', calls)
            self.assertIn('device_config put connectivity override_tether_enable_bpf_offload true', calls)
            self.assertIn('rm -f /sys/fs/bpf/ttl65ebpf_prog', calls)
            self.assertNotIn('qdisc del', calls)


if __name__ == '__main__':
    unittest.main()
