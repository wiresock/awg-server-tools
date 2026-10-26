"""Exercise the real shell checksum writer, including failed hash commands."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/boringtun-artifact.sh"
FIRST = "boringtun-cli-0.7.1-g0123456789ab-linux-aarch64-musl.tar.gz"
SECOND = "boringtun-cli-0.7.1-g0123456789ab-linux-x86_64-musl.tar.gz"


@unittest.skipIf(os.name == "nt", "requires the production Bash environment")
class ArtifactChecksumTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / FIRST).write_bytes(b"first")
        (self.directory / SECOND).write_bytes(b"second")
        self.sums = self.directory / "SHA256SUMS"
        self.original = b"previous complete checksums\n"
        self.sums.write_bytes(self.original)

    def run_writer(self, output=None, status=0):
        # Override only the failing external hashing boundary. The writer,
        # enumeration, output handling and final replacement remain real.
        code = 'source "$1"\n'
        if output is not None:
            code += '''
bta_sha256() {
    if [[ "$1" == *linux-x86_64-musl.tar.gz ]]; then
        printf '%s' "$BTA_TEST_HASH_OUTPUT"
        return "$BTA_TEST_HASH_STATUS"
    fi
    printf '%064d\n' 0
}
'''
        code += 'bta_checksums "$2"\n'
        env = dict(os.environ, BTA_TEST_HASH_OUTPUT=output or "", BTA_TEST_HASH_STATUS=str(status))
        return subprocess.run(["bash", "-c", code, "checksum-test", str(SCRIPT), str(self.directory)],
                              env=env, capture_output=True, text=True)

    def assert_preserved_failure(self, output, status=0):
        result = self.run_writer(output, status)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sums.read_bytes(), self.original)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), sorted([FIRST, SECOND, "SHA256SUMS"]))

    def test_success_writes_complete_sorted_real_digests(self):
        result = self.run_writer()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = f"{hashlib.sha256(b'first').hexdigest()}  {FIRST}\n{hashlib.sha256(b'second').hexdigest()}  {SECOND}\n"
        self.assertEqual(self.sums.read_text(), expected)

    def test_failed_hash_preserves_existing_checksums_and_removes_scratch(self):
        self.assert_preserved_failure("", 23)

    def test_failed_hash_with_valid_looking_stdout_still_fails(self):
        self.assert_preserved_failure("a" * 64, 23)

    def test_empty_or_malformed_hash_preserves_existing_checksums(self):
        for output in ("", "bad", "A" * 64, "a" * 63, "a" * 65, "a" * 64 + " extra", "a" * 32 + "\n" + "a" * 32):
            with self.subTest(output=output):
                self.assert_preserved_failure(output)

    def test_failed_hash_creates_no_checksum_file_when_none_existed(self):
        self.sums.unlink()
        result = self.run_writer("", 23)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), sorted([FIRST, SECOND]))


if __name__ == "__main__":
    unittest.main()
