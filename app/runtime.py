"""Explicit local/cloud modes. Hosting detection never silently enables cloud mode."""
import os


def cloud_mode():
    mode = os.getenv('USB_RUNTIME_MODE', 'local')
    if mode not in ('local', 'azure'):
        raise ValueError('USB_RUNTIME_MODE must be local or azure')
    return mode == 'azure'


def require_local_runtime():
    # Compatibility name: explicit cloud mode is now supported.
    if not cloud_mode() and any(os.getenv(key) for key in ('WEBSITE_INSTANCE_ID', 'WEBSITE_SITE_NAME')):
        raise RuntimeError('Azure hosting is disabled unless USB_RUNTIME_MODE=azure. See DEPLOYMENT.md.')


def write_flag(name, filename):
    if cloud_mode():
        return os.getenv('USB_CLOUD_SAMPLE_WRITES') == '1' and os.getenv(name) == '1'
    from dotenv import dotenv_values
    from .store import ROOT
    return dotenv_values(ROOT/filename).get(name) == '1'
