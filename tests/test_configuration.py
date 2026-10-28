import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from app.configuration import ConfigurationError, deployment_json
from app.store import ROOT
from usb_functions.api import create_business_api
from usb_functions.bridge import sign_request


def test_private_metadata_binds_targets_without_source_changes():
    directory = json.loads((ROOT/'config/sample-tenant-resources.json').read_text(encoding='utf-8'))
    directory['tenant_id'] = '10000000-0000-0000-0000-000000000011'
    directory['user_group']['id'] = '10000000-0000-0000-0000-000000000012'
    directory['device_group']['id'] = '10000000-0000-0000-0000-000000000013'
    directory['policy'] = {'id':'10000000-0000-0000-0000-000000000014','name':'USB-TEST-PRIVATE-TARGET'}
    for i, row in enumerate(directory['users'],1):
        row['upn'] = f'usb.sample{i:03d}@private.example.invalid'
    source = json.loads((ROOT/'config/read-sources.json').read_text(encoding='utf-8'))
    source['tenant_id'] = directory['tenant_id']
    code = '''
import copy
from usb_functions.sample_directory import SampleDirectory, TENANT, USERS, PCS, DOMAIN, LabError
from usb_functions.pair_policy import POLICY_ID, POLICY_NAME
from usb_functions.read_sources import ReadSources
s=SampleDirectory(None,TENANT,enabled=False)
assert TENANT=='10000000-0000-0000-0000-000000000011'
assert USERS=='10000000-0000-0000-0000-000000000012'
assert PCS=='10000000-0000-0000-0000-000000000013'
assert DOMAIN=='private.example.invalid'
assert POLICY_ID=='10000000-0000-0000-0000-000000000014'
assert POLICY_NAME=='USB-TEST-PRIVATE-TARGET'
assert ReadSources(TENANT).config['tenant_id']==TENANT
bad=copy.deepcopy(s.config);bad['user_group']['id']=PCS
try:SampleDirectory(None,TENANT,config=bad,enabled=False)
except LabError:pass
else:raise AssertionError('Runtime caller cannot override the declared target')
'''
    env = dict(os.environ, USB_SAMPLE_DIRECTORY_JSON=json.dumps(directory), USB_READ_SOURCES_JSON=json.dumps(source))
    result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('value', ['[1,2]', '{invalid-private-value'])
def test_invalid_private_configuration_fails_without_echoing_value(monkeypatch, value):
    monkeypatch.setenv('USB_READ_SOURCES_JSON', value)
    with pytest.raises(ConfigurationError) as exc:
        deployment_json('USB_READ_SOURCES_JSON', 'read-sources.json')
    assert value not in str(exc.value)


def test_unconfigured_tenant_is_a_structured_error_not_internal_server_error(tmp_path):
    tenant = '10000000-0000-0000-0000-000000000099'
    key = 'test-configuration-bridge-key-at-least-forty-eight-characters'
    app = create_business_api(tmp_path/'config.sqlite3', key, tenant)
    user = {'source':'entra','tenant_id':tenant,'username':'operator@example.invalid','oid':'test-operator','roles':['USB.Operator']}
    path = '/api/sample-directory/mappings'
    response = TestClient(app).get(path, headers={'X-USB-Assertion':sign_request(key,user,'GET',path,b'')})
    assert response.status_code == 503
    assert response.json()['code'] == 'configuration_required'
    assert 'Traceback' not in response.text
