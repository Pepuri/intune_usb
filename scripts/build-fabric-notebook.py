"""Create an offline importable Fabric notebook. No service calls."""
import json
import hashlib
from pathlib import Path

root=Path(__file__).resolve().parents[1]
source=(root/'notebooks/usb_lakehouse_worker.py').read_text(encoding='utf-8')
cells=[]
for part in source.split('# %%'):
    if not part.strip():continue
    first,_,body=part.partition('\n')
    markdown='[markdown]' in first
    text='\n'.join(line.removeprefix('# ') for line in body.splitlines()) if markdown else body
    metadata={'tags':['parameters']} if 'parameters' in first else {}
    cell={'id':hashlib.sha256(text.encode()).hexdigest()[:12], 'cell_type':'markdown' if markdown else 'code','metadata':metadata,'source':text.splitlines(keepends=True)}
    if not markdown:cell.update(execution_count=None,outputs=[])
    cells.append(cell)
notebook={'cells':cells,'metadata':{'kernelspec':{'display_name':'Synapse PySpark','language':'python','name':'synapse_pyspark'},
          'language_info':{'name':'python'}},'nbformat':4,'nbformat_minor':5}
target=root/'notebooks/usb_lakehouse_worker.ipynb'
target.write_text(json.dumps(notebook,ensure_ascii=False,indent=2),encoding='utf-8')
print('Offline notebook created:',target.name)
