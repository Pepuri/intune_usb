"""Offline source/ZIP audit. Never prints secret values or publishes anything."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid
import zipfile

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'.git', '.venv', '.tools', '.data', '.functions-log', '.pytest_cache',
             '__pycache__', '.python_packages', 'node_modules', '.azure', '.vscode',
             'artifacts', 'dist', 'build'}
PATTERNS = {
    'private_key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'github_token': re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'bearer_token': re.compile(rb'(?i)Bearer\s+[A-Za-z0-9_.-]{60,}'),
    'azure_storage_key': re.compile(rb'(?i)AccountKey=[A-Za-z0-9+/]{40,}={0,2}'),
    'jwt_literal': re.compile(rb'\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b'),
    'credential_literal': re.compile(rb'''(?i)(?:ENTRA_CLIENT_SECRET|USB_FUNCTION_BRIDGE_KEY|client_secret|password)["']?\s*[:=]\s*["']([^"'\r\n]{20,})["']'''),
}
ALLOWED_ROOT = {'.gitignore', '.funcignore', '.env.example', 'host.json',
                'local.settings.example.json', 'function_app.py', 'LICENSE'}
ALLOWED_FOLDERS = {'app', 'usb_functions', 'tests', 'scripts', 'config', 'sample_data', 'deploy', 'notebooks', '.github'}
SECRET_HINT = re.compile(r'secret|password|token|bridge_key|connectionstring|accountkey', re.I)


def known_secrets(root):
    found = set()
    for path in root.glob('.env*'):
        if path.name.endswith('.example'):
            continue
        for key, value in dotenv_values(path).items():
            if value and len(value) >= 12 and SECRET_HINT.search(key):
                found.add(value.encode())
    path = root/'local.settings.json'
    if path.exists():
        for key, value in json.loads(path.read_text(encoding='utf-8-sig')).get('Values', {}).items():
            if isinstance(value, str) and len(value) >= 12 and SECRET_HINT.search(key):
                found.add(value.encode())
    return found


def scan_bytes(name, raw, known):
    findings = []
    if any(value in raw for value in known):
        findings.append({'path': name, 'rule': 'known_local_secret'})
    for rule, pattern in PATTERNS.items():
        for match in pattern.finditer(raw):
            if rule == 'credential_literal':
                value = match.group(1).lower()
                if re.fullmatch(rb'@microsoft\.keyvault\(secreturi=https://[^/\s]+\.vault\.azure\.net/secrets/[^\s)]+\)', value):
                    continue
                # Explicit test fixtures are not credentials; exact local-secret checks still apply.
                if any(word in value for word in (b'test', b'example', b'placeholder', b'never-store', b'your-')):
                    continue
            findings.append({'path': name, 'rule': rule})
            break
    return findings


def all_files(root):
    paths = []
    for folder, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith('.egg-info')]
        paths.extend((Path(folder)/name).relative_to(root).as_posix() for name in names)
    return sorted(paths)


def git_ignored(root, paths):
    # Use Git's actual ignore engine without initializing/modifying the user's project.
    with tempfile.TemporaryDirectory(prefix='usb-release-ignore-') as folder:
        subprocess.run(['git', 'init', '--quiet', folder], check=True, capture_output=True)
        (Path(folder)/'.gitignore').write_bytes((root/'.gitignore').read_bytes())
        empty = Path(folder)/'.git/empty-global-ignore'
        empty.write_text('', encoding='utf-8')
        result = subprocess.run(['git', '-c', 'core.excludesFile='+str(empty), '-c', 'core.ignoreCase=false',
                                 '-C', folder, 'check-ignore', '--no-index', '-z', '--stdin'],
                                input=('\0'.join(paths)+'\0').encode(), capture_output=True)
        if result.returncode not in (0, 1):
            raise RuntimeError('Git ignore verification failed')
        return set(result.stdout.decode().split('\0')) - {''}


def reviewable(path):
    parts = Path(path).parts
    if len(parts) == 1:
        return path in ALLOWED_ROOT or path.endswith(('.md', '.ps1', '.cmd')) or bool(re.fullmatch(r'requirements(?:-dev|-lock|-fabric)?\.txt', path))
    return parts[0] in ALLOWED_FOLDERS and Path(path).suffix.lower() in {
        '.py', '.js', '.html', '.css', '.json', '.xml', '.csv', '.md', '.txt', '.ipynb', '.yml'}


def audit(root=ROOT):
    paths = all_files(root)
    # Probe future credential filenames as well as actual existing files.
    private = ['.env', '.env.local', '.env.functions', '.env.pair-policy', '.env.sample-directory',
               'local.settings.json', '.data/demo.sqlite3', 'evidence/capture.png',
               'credentials.pem', 'credentials.key', 'identity.pfx', 'identity.p12',
               'app.PublishSettings', 'app.pubxml.user', 'backup.db', 'archive.zip',
               '.azure/accessTokens.json', '.vscode/settings.json', 'dist/package.zip']
    ignored = git_ignored(root, paths+private)
    findings = [{'path': p, 'rule': 'private_path_not_ignored'} for p in private if p not in ignored]
    candidates = [p for p in paths if p not in ignored]
    known = known_secrets(root)
    manifest = []
    for name in candidates:
        path = root/name
        if path.is_symlink():
            findings.append({'path': name, 'rule': 'symlink_requires_review'})
            continue
        if not reviewable(name):
            findings.append({'path': name, 'rule': 'unexpected_source_file'})
        raw = path.read_bytes()
        findings.extend(scan_bytes(name, raw, known))
        manifest.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    tracked = []
    if (root/'.git').exists():
        result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], capture_output=True, check=True)
        tracked = [p for p in result.stdout.decode().split('\0') if p]
        # Already tracked secrets remain tracked even after .gitignore is changed.
        for name in tracked:
            if name not in candidates:
                findings.append({'path': name, 'rule': 'tracked_excluded_file_requires_review'})
    return {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'source_scan_passed': not findings,
            'git_repository_exists': (root/'.git').exists(), 'tracked_file_count': len(tracked),
            'source_file_count': len(manifest), 'excluded_file_count': len(paths)-len(candidates),
            'known_secret_values_checked': len(known), 'findings': findings, 'files': manifest,
            'azure_deployment_ready': False,
            'limitations': ['Not a full history scan or proof that unknown secrets cannot exist.',
                           'Customer identity sanitization requires a separate environment-identifier audit.',
                           'Source audit is not cloud deployment validation. See DEPLOYMENT.md for runtime verification.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true', help='Build reviewed source ZIP only; never deploy')
    args = parser.parse_args()
    report = audit()
    folder = ROOT/'.data/evidence'
    folder.mkdir(parents=True, exist_ok=True)
    if report['source_scan_passed'] and args.build:
        output = ROOT.parent/'artifacts/usb-operations-source-20261028.zip'
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name+'.'+uuid.uuid4().hex+'.tmp')
        try:
            with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as package:
                for item in report['files']:
                    raw = (ROOT/item['path']).read_bytes()
                    if hashlib.sha256(raw).hexdigest() != item['sha256']:
                        raise RuntimeError('Source changed during packaging; run the audit again.')
                    package.writestr(item['path'], raw)
            with zipfile.ZipFile(temporary) as package:
                assert set(package.namelist()) == {i['path'] for i in report['files']}
                known = known_secrets(ROOT)
                archive_findings = [hit for name in package.namelist()
                                    for hit in scan_bytes(name, package.read(name), known)]
            if archive_findings:
                report['findings'].extend(archive_findings)
                report['source_scan_passed'] = False
            else:
                temporary.replace(output)
                report['source_zip'] = {'path': str(output), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                                        'archive_scan_passed': True}
        finally:
            temporary.unlink(missing_ok=True)
    (folder/'release-audit-20261028.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k != 'files'}, ensure_ascii=False, indent=2))
    return 0 if report['source_scan_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
