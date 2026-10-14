#!/usr/bin/env python3
"""Offline installer integration tests; no network or installed binary changes."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / 'install.sh'


class InstallTests(unittest.TestCase):
    def run_case(self, system='Linux', arch='x86_64', corrupt=False, missing=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mocks = root / 'mocks'
            mocks.mkdir()
            install = root / 'install with spaces'
            install.mkdir()
            (install / 'cayman').write_text('original')
            platform = ('darwin' if system == 'Darwin' else 'linux')
            cpu = 'arm64' if arch in ('arm64', 'aarch64') else 'amd64'
            asset = f'cayman-{platform}-{cpu}'
            data = b'#!/bin/bash\necho "cayman test version"\n'
            (root / asset).write_bytes(data)
            digest = hashlib.sha256((root / asset).read_bytes()).hexdigest()
            (root / (asset + '.sha256')).write_text(
                f'{"0" * 64 if corrupt else digest}  {asset}\n')
            (mocks / 'uname').write_text(
                '#!/bin/bash\nif [[ "$1" == -s ]]; then echo "$TEST_OS"; else echo "$TEST_ARCH"; fi\n')
            (mocks / 'curl').write_text('''#!/bin/bash
out=''
for ((i=1;i<=$#;i++)); do
  if [[ "${!i}" == -o ]]; then j=$((i+1)); out=${!j}; fi
done
url=${!#}
if [[ "$url" == */latest ]]; then
  printf 'https://github.com/octays/cayman/releases/tag/v0.1.0'
else
  [[ "$TEST_MISSING" == 0 ]] || exit 22
  cp "$TEST_FIXTURE/${url##*/}" "$out"
fi
''')
            for path in mocks.iterdir():
                path.chmod(0o755)
            result = subprocess.run(['bash', str(SCRIPT)], env={
                **os.environ, 'PATH': f'{mocks}:{os.environ["PATH"]}',
                'TEST_OS': system, 'TEST_ARCH': arch, 'TEST_FIXTURE': str(root),
                'TEST_MISSING': str(int(missing)), 'CAYMAN_INSTALL_DIR': str(install),
            }, capture_output=True, text=True)
            if corrupt or missing or system == 'FreeBSD' or arch == 'riscv64':
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((install / 'cayman').read_text(), 'original')
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((install / 'cayman').read_bytes(), data)
                self.assertTrue(os.access(install / 'cayman', os.X_OK))
            self.assertFalse(list(install.glob('.cayman-install.*')))

    def test_supported_platforms(self):
        for system, arch in [('Linux', 'x86_64'), ('Linux', 'aarch64'),
                             ('Darwin', 'x86_64'), ('Darwin', 'arm64')]:
            with self.subTest(system=system, arch=arch):
                self.run_case(system, arch)

    def test_bad_checksum_preserves_existing_install(self):
        self.run_case(corrupt=True)

    def test_missing_asset_preserves_existing_install(self):
        self.run_case(missing=True)

    def test_unsupported_platform(self):
        self.run_case(system='FreeBSD')
        self.run_case(arch='riscv64')


if __name__ == '__main__':
    unittest.main()
