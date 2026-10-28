"""Transactional SQLite queue and mock policy publisher. No network publisher exists."""
import hashlib
import json
import sqlite3
import time
import uuid
from datetime import date, datetime, timezone


def stamp():
    return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def allowed(row, day):
    return (not row.get('sample_group_key') and row['approval_status'] in ('active','deployment_pending') and row['validation_status']=='verified'
            and row['valid_from_date']<=day.isoformat()<=row['valid_until_date']
            and (row['permission']!='read_write' or row['bitlocker_state']=='encrypted'))


class Workflow:
    def __init__(self, store, reference_date):
        self.store=store
        self._reference_date=reference_date
        with store.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, dedupe TEXT UNIQUE, kind TEXT, payload TEXT, status TEXT,
                attempts INTEGER, max_attempts INTEGER, available REAL, lease_until REAL, lease_token TEXT,
                error TEXT, created TEXT, updated TEXT, result TEXT)''')
            db.execute('''CREATE TABLE IF NOT EXISTS job_runs (
                id TEXT PRIMARY KEY, job_id TEXT, attempt INTEGER, started TEXT, finished TEXT,
                status TEXT, source TEXT, error TEXT)''')
            if not store.get(db,'policy','current'):
                seed=[r for r in store.rows(db,'approvals') if r['deployment_status']=='device_applied' and allowed(r,self.reference_date)]
                store.save(db,'policy','current',self.manifest(seed,[],source='sample-seed'))

    @property
    def reference_date(self):
        if self._reference_date is None:
            from .pair_policy import kst_day
            return kst_day()
        return self._reference_date

    @reference_date.setter
    def reference_date(self, value):
        self._reference_date=value

    @staticmethod
    def pair(row):
        return {k:row[k] for k in ('approval_id','user_object_id','usb_serial','permission','valid_until_date')}

    def fingerprint(self, db):
        rows=self.store.rows(db,'approvals')+self.store.rows(db,'pcs')
        return digest({'date':self.reference_date.isoformat(),'rows':sorted(
            (r.get('approval_id',r.get('device_id')),r.get('revision',1)) for r in rows)})

    def preview(self, db):
        rows=self.store.rows(db,'approvals')
        permits=[r for r in rows if allowed(r,self.reference_date)]
        withdrawals=[r for r in rows if not r.get('sample_group_key') and (r['deployment_status']=='withdrawal_pending' or
                     (r['approval_status'] in ('active','deployment_pending') and r['valid_until_date']<self.reference_date.isoformat()
                      and r['deployment_status'] not in ('withdrawal_published','withdrawal_confirmed')))]
        pairs=[self.pair(r) for r in permits]
        return {'pairs':pairs,'withdrawals':[r['approval_id'] for r in withdrawals],
                'pending':[r['approval_id'] for r in permits if r['deployment_status'] in ('publish_pending','publish_failed')],
                'excluded':len(rows)-len(permits),'manifest_bytes':len(json.dumps(pairs,ensure_ascii=False).encode()),
                'target_pcs':[r['device_name'] for r in self.store.rows(db,'pcs') if r['exception_assignment']=='allowed'],
                'fingerprint':self.fingerprint(db)}

    def manifest(self, rows, targets, source='mock-publish'):
        pairs=[self.pair(r) if 'approval_status' in r else dict(r) for r in rows]
        pairs.sort(key=lambda r:r['approval_id'])
        body={'format':'usb-local-policy-manifest-v1','deployable_to_intune':False,'publisher':'mock',
              'reference_date':self.reference_date.isoformat(),'pairs':pairs,'target_pcs':sorted(targets),
              'baseline_block_required':True,'bitlocker_write_required':True,'source':source}
        body['version']=digest(body)
        body['bytes']=len(json.dumps(body,ensure_ascii=False).encode())
        return body

    def enqueue(self, db, kind, payload, dedupe):
        existing=db.execute('SELECT id FROM jobs WHERE dedupe=?',(dedupe,)).fetchone()
        if existing:
            return self.get(db,existing[0]),True
        key='JOB-'+uuid.uuid4().hex[:12].upper()
        created=stamp()
        db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (key,dedupe,kind,json.dumps(payload,ensure_ascii=False),'queued',0,3,time.time(),0,'','',created,created,'{}'))
        return self.get(db,key),False

    def enqueue_publish(self, fingerprint, requester, simulate_failures=0):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            plan=self.preview(db)
            if fingerprint!=plan['fingerprint']:
                raise ValueError('원장이 변경되었습니다. 미리보기를 다시 확인해 주세요.')
            keys=plan['pending']+plan['withdrawals']
            if not keys:
                return None,False
            payload={'fingerprint':fingerprint,'reference_date':self.reference_date.isoformat(),'keys':keys,
                     'withdrawals':plan['withdrawals'],'pairs':plan['pairs'],'target_pcs':plan['target_pcs'],
                     'requester':requester,'simulate_failures':simulate_failures}
            return self.enqueue(db,'publish',payload,'publish:'+fingerprint)

    def get(self, db, key, private=False):
        db.row_factory=sqlite3.Row
        row=db.execute('SELECT * FROM jobs WHERE id=?',(key,)).fetchone()
        db.row_factory=None
        if not row:return None
        result=dict(row)
        payload=json.loads(result.pop('payload'))
        result['result']=json.loads(result['result'])
        result.update(item_count=len(payload['keys']),requester=payload['requester'],reference_date=payload['reference_date'])
        result.pop('dedupe',None)
        if private:result['payload']=payload
        else:result.pop('lease_token',None)
        result['attempt_history']=[dict(zip(('attempt','started','finished','status','source','error'),r)) for r in db.execute(
            'SELECT attempt,started,finished,status,source,error FROM job_runs WHERE job_id=? ORDER BY started DESC LIMIT 10',(key,)).fetchall()]
        return result

    def jobs(self):
        with self.store.connect() as db:
            return [self.get(db,r[0]) for r in db.execute('SELECT id FROM jobs ORDER BY created DESC').fetchall()]

    def history(self, db, row, before, action, who, description):
        key='FUNCTION-EVT-'+uuid.uuid4().hex
        self.store.save(db,'history',key,{'event_id':key,'is_sample':True,'approval_id':row['approval_id'],
                        'user_upn':row['user_upn'],'usb_id':row['usb_id'],'event_type':action,
                        'old_status':before['approval_status'],'new_status':row['approval_status'],
                        'actor_upn':who,'event_at_utc':stamp(),'description':description,'before':before,'after':row.copy()})

    def claim(self, job_id=None, clock=None):
        clock=time.time() if clock is None else clock
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            query="SELECT id FROM jobs WHERE ((status IN ('queued','retry_wait') AND available<=?) OR (status='processing' AND lease_until<=?))"
            params=[clock,clock]
            if job_id: query+=' AND id=?';params.append(job_id)
            query+=' ORDER BY created LIMIT 1'
            hit=db.execute(query,params).fetchone()
            if not hit:return None
            key=hit[0]
            job=self.get(db,key,private=True)
            if job['attempts']>=job['max_attempts']:
                db.execute("UPDATE jobs SET status='dead_letter',error=?,updated=? WHERE id=?",('작업 lease 복구 한도 초과',stamp(),key))
                return None
            token=uuid.uuid4().hex
            if job['status']=='processing':
                db.execute("UPDATE job_runs SET status='lease_expired',finished=? WHERE id=? AND status='processing'",(stamp(),job['lease_token']))
            db.execute("UPDATE jobs SET status='processing',attempts=attempts+1,lease_until=?,lease_token=?,updated=? WHERE id=?",
                       (clock+30,token,stamp(),key))
            db.execute('INSERT INTO job_runs VALUES (?,?,?,?,?,?,?,?)',(token,key,job['attempts']+1,stamp(),'','processing','',''))
            return self.get(db,key,private=True)

    def execute(self, job, source='direct-worker'):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current=self.get(db,job['id'],private=True)
            if current['status']!='processing' or current['lease_token']!=job['lease_token']:
                return 'lease_lost'
            if current['lease_until']<time.time():return 'lease_expired'
            db.execute('UPDATE job_runs SET source=? WHERE id=?',(source,job['lease_token']))
            payload=current['payload']
            if payload['fingerprint']!=self.fingerprint(db) or payload['reference_date']!=self.reference_date.isoformat():
                db.execute("UPDATE jobs SET status='superseded',error=?,updated=? WHERE id=?",('원장 또는 기준일 변경 · 미리보기 후 다시 게시 필요',stamp(),job['id']))
                db.execute("UPDATE job_runs SET status='superseded',finished=?,error=? WHERE id=?",(stamp(),'원장 또는 기준일 변경',job['lease_token']))
                return 'superseded'
            if current['attempts']<=payload.get('simulate_failures',0):
                terminal=current['attempts']>=current['max_attempts']
                state='dead_letter' if terminal else 'retry_wait'
                message='의도적으로 발생시킨 로컬 모의 배포 실패'
                db.execute('UPDATE jobs SET status=?,available=?,lease_until=0,error=?,updated=? WHERE id=?',
                           (state,time.time()+2**current['attempts'],message,stamp(),job['id']))
                db.execute('UPDATE job_runs SET status=?,finished=?,error=? WHERE id=?',(state,stamp(),message,job['lease_token']))
                if terminal:
                    for key in payload['keys']:
                        row=self.store.get(db,'approvals',key)
                        if key not in payload['withdrawals']:
                            row.update(deployment_status='publish_failed',last_error=message)
                            self.store.save(db,'approvals',key,row)
                return state
            if current['kind']=='expiry':
                base=self.store.get(db,'policy','current')['pairs']
                pairs=[p for p in base if p['approval_id'] not in payload['withdrawals'] and p['valid_until_date']>=self.reference_date.isoformat()]
            else:
                pairs=payload['pairs']
            manifest=self.manifest(pairs,payload['target_pcs'])
            for key in payload['keys']:
                row=self.store.get(db,'approvals',key)
                before=row.copy()
                withdrawing=key in payload['withdrawals']
                if withdrawing and row['valid_until_date']<self.reference_date.isoformat() and row['approval_status']!='revoked':row['approval_status']='expired'
                row.update(deployment_status='withdrawal_published' if withdrawing else 'published',
                           deployment_version=row.get('ledger_version',1),revision=row.get('revision',1)+1,
                           updated_at_utc=stamp(),last_error='')
                self.store.save(db,'approvals',key,row)
                self.history(db,row,before,'simulated_publish',payload['requester'],
                             'Function 모의 회수 게시 · 단말 확인 대기' if withdrawing else 'Function 모의 허용 게시 · 단말 적용 대기')
            self.store.save(db,'policy','current',manifest)
            self.store.save(db,'snapshots',job['id'],manifest)
            result={'processed':len(payload['keys']),'snapshot_version':manifest['version'],'publisher':'mock','device_confirmed':False,'execution_source':source}
            db.execute("UPDATE jobs SET status='succeeded',result=?,lease_until=0,error='',updated=? WHERE id=?",
                       (json.dumps(result),stamp(),job['id']))
            db.execute("UPDATE job_runs SET status='succeeded',finished=? WHERE id=?",(stamp(),job['lease_token']))
            return 'succeeded'

    def drain(self, limit=20, source='manual'):
        outcomes=[]
        for _ in range(limit):
            job=self.claim()
            if not job:break
            outcomes.append({'job_id':job['id'],'status':self.execute(job,source=source)})
        with self.store.connect() as db:
            self.store.save(db,'runtime','worker',{'last_run_at':stamp(),'source':source,'outcomes':outcomes,'publisher':'mock'})
        return {'outcomes':outcomes,'source':source,'publisher':'mock'}

    def retry(self, key, requester):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            job=self.get(db,key,private=True)
            if not job:raise LookupError('작업을 찾을 수 없습니다.')
            if job['status'] not in ('dead_letter','retry_wait'):raise ValueError('실패·재시도 대기 작업만 재시도할 수 있습니다.')
            if job['payload']['fingerprint']!=self.fingerprint(db):raise ValueError('원장이 변경되어 다시 미리보기가 필요합니다.')
            payload=job['payload'];payload['simulate_failures']=0;payload['retry_by']=requester
            db.execute("UPDATE jobs SET status='queued',attempts=0,available=?,lease_until=0,error='',payload=?,updated=? WHERE id=?",
                       (time.time(),json.dumps(payload,ensure_ascii=False),stamp(),key))
            return self.get(db,key)

    def expire(self, source='manual'):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            expired=[]
            for row in self.store.rows(db,'approvals'):
                if row.get('sample_group_key'):continue
                if row['approval_status'] not in ('active','deployment_pending','verification_pending') or row['valid_until_date']>=self.reference_date.isoformat():continue
                before=row.copy()
                posted=row.get('deployment_version',0)>0 or row['deployment_status'] in ('published','device_applied')
                row.update(approval_status='expired',deployment_status='withdrawal_pending' if posted else 'not_published',
                           revision=row.get('revision',1)+1,ledger_version=row.get('ledger_version',1)+1,updated_at_utc=stamp())
                self.store.save(db,'approvals',row['approval_id'],row)
                self.history(db,row,before,'expired','local.function@example.invalid','Function 만료 판정 · 단말 회수 확인은 별도')
                if posted:expired.append(row['approval_id'])
            # Reconcile unfinished expirations as well; a superseded queue message must not lose a withdrawal.
            pending=[r['approval_id'] for r in self.store.rows(db,'approvals') if r['approval_status']=='expired' and r['deployment_status']=='withdrawal_pending']
            job=None
            if pending:
                payload={'fingerprint':self.fingerprint(db),'reference_date':self.reference_date.isoformat(),'keys':pending,
                         'withdrawals':pending,'pairs':[],'target_pcs':[p['device_name'] for p in self.store.rows(db,'pcs') if p['exception_assignment']=='allowed'],
                         'requester':'local.function@example.invalid','simulate_failures':0}
                job,_=self.enqueue(db,'expiry',payload,'expiry:'+payload['fingerprint'])
            run={'last_run_at':stamp(),'source':source,'newly_expired_posted':expired,'withdrawals':pending,'job_id':job['id'] if job else None}
            self.store.save(db,'runtime','expiry',run)
            return run
