"""Cross-check public schema-2 metadata against reviewed installer constants.

This is an availability/integrity check. The adoption command separately verifies
signatures and live CI provenance before these constants enter the installer.
"""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import boringtun_release_policy as policy


def checksum_contract(installer, raw):
    data = policy.check_descriptor(policy.load_json(raw))
    if raw != policy.canonical_bytes(data):
        raise policy.PolicyError('noncanonical RELEASE.json')

    def value(name):
        found = re.findall(rf'^AWG_BT_RELEASE_{name}="([^"\r\n]*)"$', installer, re.M)
        if len(found) != 1:
            raise policy.PolicyError(f'missing or duplicate installer constant {name}')
        return found[0]

    for key, field in (('TAG', 'tag'), ('SOURCE_COMMIT', 'source_commit'), ('VERSION', 'version'), ('BUILD', 'build')):
        if value(key) != str(data[field]):
            raise policy.PolicyError(f'public descriptor differs from installer {key}')
    if value('SOURCE_REPOSITORY') != 'https://github.com/' + data['repository']:
        raise policy.PolicyError('public source repository differs from installer')
    for item in data['archives']:
        if item['target'].endswith('-apple-darwin'):
            continue
        arch = item['target'].split('-')[0].upper()
        for key, field in (('ASSET', 'name'), ('ARCHIVE_SHA256', 'sha256'), ('BINARY_SHA256', 'binary_sha256')):
            if value(f'{key}_{arch}') != item[field]:
                raise policy.PolicyError(f'public archive differs from installer {key}_{arch}')
    return ''.join(f"{item['sha256']}  {item['name']}\n" for item in sorted(data['archives'], key=lambda item:item['name']))


if __name__ == '__main__':
    try:
        sys.stdout.write(checksum_contract(Path(sys.argv[1]).read_text(), Path(sys.argv[2]).read_bytes()))
    except (OSError, ValueError, policy.PolicyError) as error:
        sys.exit(f'public release contract: {error}')
