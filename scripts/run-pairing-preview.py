"""Isolated local UI demo. Never loads tenant credentials or starts Function timers."""
import os
import sys
import argparse
from datetime import date, datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ['USB_RUNTIME_MODE'] = 'local'
os.environ['USB_AUTH_MODE'] = 'demo'
os.environ['USB_FUNCTION_URL'] = 'http://127.0.0.1:7071'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='USB/MTP isolated local ledger preview')
    parser.add_argument('--reference-date', type=date.fromisoformat,
                        default=datetime.now(timezone(timedelta(hours=9))).date())
    args = parser.parse_args()
    os.environ['USB_DEMO_DATE'] = args.reference_date.isoformat()
    import uvicorn
    from app.auth import AuthSettings
    from app.main import create_app
    app = create_app(db_path=ROOT/'.data/ppt-pairing-preview.sqlite3', auth_settings=AuthSettings())
    uvicorn.run(app, host='127.0.0.1', port=8877, access_log=False)
