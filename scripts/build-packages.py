"""Build separate source packages offline; never authenticate, publish or deploy."""
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_check', ROOT/'scripts/check-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def build(root=ROOT):
    report = release.audit(root)
    if not report['source_scan_passed']:
        raise RuntimeError('Source audit failed: '+json.dumps(report['findings']))
    files = {item['path']: item for item in report['files']}
    common = {name for name in files if name.startswith(('app/', 'usb_functions/', 'sample_data/'))
              or name in {'requirements.txt', 'requirements-lock.txt', 'config/read-sources.json',
                          'config/sample-tenant-resources.json'}}
    # Python imports are shared. Entry points and service settings remain separate.
    selections = {'web': common,
                  'function': common | {'function_app.py', 'host.json'},
                  'fabric-worker': common | {'requirements-fabric.txt'}}
    output = root/'dist'
    output.mkdir(exist_ok=True)
    manifest = {'deployments_performed': False, 'packages': {}}
    known = release.known_secrets(root)
    for service, names in selections.items():
        missing = names-files.keys()
        if missing:
            raise RuntimeError('Missing package inputs: '+str(sorted(missing)))
        target = output/(service+'.zip')
        temporary = output/(service+'.tmp')
        try:
            with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as package:
                for name in sorted(names):
                    raw = (root/name).read_bytes()
                    if hashlib.sha256(raw).hexdigest() != files[name]['sha256']:
                        raise RuntimeError('Source changed while packaging')
                    entry = zipfile.ZipInfo(name)
                    entry.create_system = 3
                    entry.external_attr = 0o100644 << 16
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    package.writestr(entry, raw)
            with zipfile.ZipFile(temporary) as package:
                if set(package.namelist()) != names:
                    raise RuntimeError('Archive layout mismatch')
                for name in package.namelist():
                    if release.scan_bytes(name, package.read(name), known):
                        raise RuntimeError('Archive secret scan failed')
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        manifest['packages'][service] = {'path': target.name, 'file_count': len(names),
                                         'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(manifest, indent=2))
    return manifest


if __name__ == '__main__':
    build()
