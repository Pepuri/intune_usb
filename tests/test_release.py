import importlib.util
import runpy
from pathlib import Path

import pytest

from app.main import create_app
from app.store import ROOT

spec = importlib.util.spec_from_file_location('release_check', ROOT/'scripts/check-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


@pytest.mark.parametrize('marker', ['WEBSITE_INSTANCE_ID', 'WEBSITE_SITE_NAME'])
@pytest.mark.parametrize('entrypoint', ['web', 'function'])
def test_azure_entrypoint_cannot_start_as_local_demo(monkeypatch, marker, entrypoint):
    monkeypatch.setenv(marker, 'test-cloud-instance')
    with pytest.raises(RuntimeError, match='Azure hosting is disabled'):
        if entrypoint == 'web':
            create_app()
        else:
            runpy.run_path(str(ROOT/'function_app.py'))


def release_tree(tmp_path):
    (tmp_path/'.gitignore').write_bytes((ROOT/'.gitignore').read_bytes())
    (tmp_path/'app').mkdir()
    (tmp_path/'app/main.py').write_text('# harmless source', encoding='utf-8')
    return tmp_path


def test_private_files_are_excluded_and_copied_secret_is_detected(tmp_path):
    root = release_tree(tmp_path)
    canary = 'canary-release-check-value-0123456789abcdef'
    (root/'.env.local').write_text('ENTRA_CLIENT_SECRET='+canary, encoding='utf-8')
    (root/'local.settings.json').write_text('{"Values":{}}', encoding='utf-8')
    result = release.audit(root)
    assert result['source_scan_passed']
    assert result['known_secret_values_checked'] == 1
    assert '.env.local' not in {f['path'] for f in result['files']}
    (root/'app/main.py').write_text('leaked = '+repr(canary), encoding='utf-8')
    result = release.audit(root)
    assert not result['source_scan_passed']
    assert {'path':'app/main.py', 'rule':'known_local_secret'} in result['findings']
    assert canary not in str(result)


def test_unexpected_file_and_unknown_token_are_blocked(tmp_path):
    root = release_tree(tmp_path)
    (root/'unreviewed.binary').write_bytes(b'not approved')
    (root/'app/main.py').write_text('value = "'+'ghp_'+'A'*36+'"', encoding='utf-8')
    result = release.audit(root)
    assert not result['source_scan_passed']
    assert {f['rule'] for f in result['findings']} >= {'unexpected_source_file','github_token'}


def test_broken_ignore_rules_fail_closed(tmp_path):
    root = release_tree(tmp_path)
    (root/'.gitignore').write_text('', encoding='utf-8')
    result = release.audit(root)
    assert not result['source_scan_passed']
    assert any(f['rule'] == 'private_path_not_ignored' for f in result['findings'])


def test_key_vault_reference_is_not_a_literal_secret():
    raw = b'"ENTRA_CLIENT_SECRET": "@Microsoft.KeyVault(SecretUri=https://<vault-name>.vault.azure.net/secrets/<web-client-secret>/)"'
    assert release.scan_bytes('deploy/plan.json', raw, set()) == []
    assert release.scan_bytes('deploy/plan.json', raw, {b'<web-client-secret>'}) == [
        {'path':'deploy/plan.json','rule':'known_local_secret'}]
