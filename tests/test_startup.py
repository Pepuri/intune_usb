"""Cloud startup must fail closed without leaking SDK credential diagnostics."""
import runpy

from fastapi.testclient import TestClient

from app.store import ROOT


def test_cloud_initialization_failure_stays_indexable_and_reveals_no_secrets(monkeypatch, caplog):
    monkeypatch.setenv('USB_RUNTIME_MODE', 'azure')
    monkeypatch.setenv('USB_FUNCTION_ALLOW_DEMO', '0')
    monkeypatch.setenv('USB_QUEUE_SCHEDULE', '0 0 * * * *')
    monkeypatch.setenv('USB_EXPIRY_SCHEDULE', '0 0 * * * *')
    canary = 'test-sensitive-connection-string-must-never-be-logged'
    def fail(*args, **kwargs):
        raise RuntimeError(canary)
    monkeypatch.setattr('usb_functions.api.create_business_api', fail)
    module = runpy.run_path(str(ROOT/'function_app.py'))
    client = TestClient(module['api'])
    for path in ('/health', '/api/state', '/api/approvals'):
        response = client.get(path)
        assert response.status_code == 503
        assert response.json()['status'] == 'initialization_failed'
        assert canary not in response.text
    assert canary not in caplog.text
    assert 'USB_INITIALIZATION_FAILED type=RuntimeError' in caplog.text
    assert module['engine'] is None
