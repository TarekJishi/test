from pathlib import Path
from uuid import uuid4
import hashlib, json, os, re, sqlite3, subprocess, tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from Registry import Registry

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.getenv("DFIR_DATA", ROOT / "data")).resolve()
UPLOADS = DATA / "uploads"
EXTRACTED = DATA / "extracted"
UPLOADS.mkdir(parents=True, exist_ok=True)
EXTRACTED.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="Forensic Workbench", version="0.2.0")
app.mount("/assets", StaticFiles(directory=ROOT / "frontend" / "assets"), name="assets")

@app.get("/")
def index(): return FileResponse(ROOT / "frontend" / "index.html")

def safe_file(fid: str, folder: Path = UPLOADS) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", fid): raise HTTPException(400, "Invalid evidence ID")
    p=(folder/fid).resolve()
    if p.parent != folder.resolve() or not p.is_file(): raise HTTPException(404,"Evidence not found")
    return p

def run_tsk(args, timeout=90):
    try: r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    except FileNotFoundError: raise HTTPException(501,"The Sleuth Kit is missing. Run the project with Docker or install mmls/fls/icat.")
    except subprocess.TimeoutExpired: raise HTTPException(408,"Forensic command timed out")
    if r.returncode: raise HTTPException(400,r.stderr[-1500:] or "The Sleuth Kit command failed")
    return r.stdout

@app.post('/api/upload')
async def upload(file: UploadFile=File(...)):
    name=Path(file.filename or 'evidence.bin').name
    suffix=Path(name).suffix.lower()
    allowed={'.dd','.img','.raw','.001','.sqlite','.sqlite3','.db','.dat','.hive','.evtx'}
    if suffix not in allowed: raise HTTPException(400,"Supported extensions: .dd .img .raw .001 .sqlite .db .dat .hive .evtx")
    fid=uuid4().hex; dest=UPLOADS/fid; size=0; sha=hashlib.sha256()
    try:
        with dest.open('wb') as out:
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>2*1024**3: raise HTTPException(413,"Starter upload limit is 2 GB")
                sha.update(chunk); out.write(chunk)
    except Exception:
        dest.unlink(missing_ok=True); raise
    return {"id":fid,"name":name,"size":size,"sha256":sha.hexdigest()}

@app.post('/api/upload-artifact')
async def upload_artifact(file: UploadFile=File(...)):
    name=Path(file.filename or 'artifact.bin').name
    suffix=Path(name).suffix.lower()
    if suffix not in {'.hive','.dat','.db','.sqlite','.sqlite3'}:
        raise HTTPException(400,"Upload a Registry hive or SQLite database")
    aid=uuid4().hex; dest=EXTRACTED/aid; size=0; sha=hashlib.sha256()
    try:
        with dest.open('wb') as out:
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>512*1024*1024: raise HTTPException(413,"Artifact upload limit is 512 MB")
                sha.update(chunk); out.write(chunk)
    except Exception:
        dest.unlink(missing_ok=True); raise
    return {"id":aid,"name":name,"size":size,"sha256":sha.hexdigest()}

@app.get('/api/evidence/{fid}/partitions')
def partitions(fid:str):
    p=safe_file(fid); return {"output":run_tsk(['mmls',str(p)])}

@app.get('/api/evidence/{fid}/files')
def files(fid:str, offset:int=Query(0,ge=0), recursive:bool=True):
    p=safe_file(fid); args=['fls','-p']
    if recursive: args.append('-r')
    if offset: args += ['-o',str(offset)]
    output=run_tsk(args+[str(p)],timeout=180)
    items=[]
    # Typical TSK format: r/r 128-128-1: Windows/System32/config/SYSTEM
    for line in output.splitlines():
        m=re.match(r'^\s*([^\s]+)\s+([^:]+):\s*(.*)$',line)
        if not m: continue
        kind,meta,path=m.groups()
        inode=meta.strip().split('-')[0]
        if not inode.isdigit(): continue
        clean=path.strip()
        items.append({"kind":kind,"meta":meta.strip(),"inode":inode,"path":clean,"name":clean.rsplit('/',1)[-1],"deleted":"*" in kind})
    return {"items":items[:25000],"total":len(items),"truncated":len(items)>25000}

@app.get('/api/evidence/{fid}/extract/{inode}')
def extract_file(fid:str,inode:str,offset:int=Query(0,ge=0),name:str='artifact.bin'):
    p=safe_file(fid)
    if not re.fullmatch(r'\d+(?:-\d+-\d+)?',inode): raise HTTPException(400,"Invalid inode")
    raw=subprocess.run(['icat','-o',str(offset),str(p),inode],capture_output=True,timeout=180)
    if raw.returncode: raise HTTPException(400,raw.stderr.decode(errors='replace')[-1000:] or 'Extraction failed')
    aid=uuid4().hex; dest=EXTRACTED/aid; dest.write_bytes(raw.stdout)
    return {"id":aid,"name":Path(name).name,"size":len(raw.stdout),"sha256":hashlib.sha256(raw.stdout).hexdigest(),"download":f"/api/artifact/{aid}/download"}

@app.get('/api/evidence/{fid}/artifacts')
def discover(fid:str,offset:int=Query(0,ge=0)):
    listing=files(fid,offset,True)['items']
    reg_names={'SYSTEM','SOFTWARE','SAM','SECURITY','DEFAULT','NTUSER.DAT','USRCLASS.DAT'}
    db_ext={'.db','.sqlite','.sqlite3'}
    found=[]
    for item in listing:
        name=item['name']; low=name.lower()
        category=None
        if name.upper() in reg_names: category='Registry hive'
        elif Path(name).suffix.lower() in db_ext: category='Possible SQLite database'
        elif low.endswith('.evtx'): category='Windows Event Log'
        elif low.endswith('.pf'): category='Prefetch'
        if category: found.append({**item,'category':category})
    return {"artifacts":found[:1000],"total":len(found)}

@app.get('/api/artifact/{aid}/download')
def download_artifact(aid:str):
    p=safe_file(aid,EXTRACTED); return FileResponse(p,filename='extracted-artifact.bin')

@app.get('/api/registry/{aid}/key')
def registry_key(aid:str,path:str=''):
    p=safe_file(aid,EXTRACTED)
    try:
        reg=Registry.Registry(str(p)); key=reg.root()
        for part in [x for x in path.replace('/','\\').split('\\') if x]: key=key.subkey(part)
        return {"name":key.name(),"path":key.path(),"subkeys":[k.name() for k in key.subkeys()],"values":[{"name":v.name(),"type":str(v.value_type()),"data":repr(v.value())[:3000]} for v in key.values()]}
    except Exception as e: raise HTTPException(400,f"Could not parse hive/key: {e}")

@app.get('/api/sqlite/{aid}/tables')
def sqlite_tables(aid:str):
    p=safe_file(aid,EXTRACTED)
    try:
        con=sqlite3.connect(f'file:{p}?mode=ro',uri=True)
        rows=con.execute("SELECT name,type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name").fetchall(); con.close()
        return {"tables":[{"name":n,"type":t} for n,t in rows]}
    except Exception as e: raise HTTPException(400,f"Not a readable SQLite database: {e}")

@app.get('/api/sqlite/{aid}/table/{table}')
def sqlite_table(aid:str,table:str,limit:int=Query(100,ge=1,le=500)):
    p=safe_file(aid,EXTRACTED)
    try:
        con=sqlite3.connect(f'file:{p}?mode=ro',uri=True); con.row_factory=sqlite3.Row
        exists=con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
        if not exists: raise HTTPException(404,'Table not found')
        q='"'+table.replace('"','""')+'"'; rows=con.execute(f'SELECT * FROM {q} LIMIT ?',(limit,)).fetchall(); con.close()
        return {"columns":list(rows[0].keys()) if rows else [],"rows":[dict(x) for x in rows]}
    except HTTPException: raise
    except Exception as e: raise HTTPException(400,str(e))

@app.get('/api/health')
def health(): return {"status":"ok","version":"0.2.0"}
