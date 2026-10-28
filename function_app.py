"""Local HTTP/timers or an Entra-protected Azure gateway for Lakehouse file commands."""
import logging
import os
from pathlib import Path

import azure.functions as func
from usb_functions.api import create_business_api
from app.store import ROOT
from app.runtime import require_local_runtime
from app.runtime import cloud_mode
from usb_functions.sample_directory import LAB_LOCK, LabError
from usb_functions.sample_ledger import SampleLedger
from usb_functions.pair_service import PairPolicyService
from usb_functions.pair_policy import PairPolicyError

require_local_runtime()
if os.getenv('USB_PUBLISH_ADAPTER','mock')!='mock':
    raise RuntimeError('This Function project only supports the approved local mock publisher')

key=os.getenv('USB_FUNCTION_BRIDGE_KEY','')
database=None if cloud_mode() else os.getenv('USB_DEMO_DB',str(ROOT/'.data/demo.sqlite3'))
api=create_business_api(database,key,os.getenv('ENTRA_TENANT_ID','22182a1f-8011-58a2-8ea1-2bab249da25a'),
                        allow_demo=os.getenv('USB_FUNCTION_ALLOW_DEMO','0')=='1')
engine=api.state.workflow
app=func.AsgiFunctionApp(app=api,http_auth_level=func.AuthLevel.ANONYMOUS if cloud_mode() else func.AuthLevel.FUNCTION,function_name='UsbBusinessHttp')


@app.timer_trigger(arg_name='timer',schedule='%USB_QUEUE_SCHEDULE%',run_on_startup=False,use_monitor=False)
def ProcessLocalJobs(timer: func.TimerRequest):
    if cloud_mode():
        return  # Fabric notebook schedule owns cloud processing.
    with LAB_LOCK:
        result=engine.drain(source='scheduled-timer')
    logging.info('USB_QUEUE_TICK source=scheduled-timer processed=%s publisher=mock',len(result['outcomes']))
    try:
        group_result = SampleLedger(api.state.store, os.getenv('ENTRA_TENANT_ID','22182a1f-8011-58a2-8ea1-2bab249da25a')).drain(source='scheduled-timer')
        if group_result['outcomes']:
            logging.info('USB_SAMPLE_LEDGER_TICK source=scheduled-timer processed=%s', len(group_result['outcomes']))
    except LabError:
        logging.warning('USB_SAMPLE_LEDGER_TICK sample configuration or connection requires attention')
    try:
        pair_result = PairPolicyService(api.state.store, os.getenv('ENTRA_TENANT_ID','22182a1f-8011-58a2-8ea1-2bab249da25a')).tick(source='scheduled-timer')
        if pair_result['status'] == 'verified':
            logging.info('USB_PAIR_POLICY_TICK source=scheduled-timer published_version=%s', pair_result['version'])
    except (PairPolicyError, LabError):
        logging.warning('USB_PAIR_POLICY_TICK candidate or sample policy requires attention')


@app.timer_trigger(arg_name='timer',schedule='%USB_EXPIRY_SCHEDULE%',run_on_startup=False,use_monitor=False)
def ScanLocalExpiry(timer: func.TimerRequest):
    if cloud_mode():
        return
    with LAB_LOCK:
        result=engine.expire(source='scheduled-timer')
    logging.info('USB_EXPIRY_TICK source=scheduled-timer newly_expired=%s publisher=mock',len(result['newly_expired_posted']))
    from usb_functions.sample_directory import SampleDirectory, LabError
    try:
        sample = SampleDirectory(api.state.store, os.getenv('ENTRA_TENANT_ID','22182a1f-8011-58a2-8ea1-2bab249da25a'))
        outcome = sample.expire(source='scheduled-timer')
        logging.info('USB_SAMPLE_EXPIRY enabled=%s outcomes=%s', outcome['enabled'], len(outcome['outcomes']))
    except LabError:
        logging.warning('USB_SAMPLE_EXPIRY sample configuration or connection requires attention')
