from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from openai import OpenAI
from pydantic import BaseModel
from supabase import create_client, Client
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import pdfplumber, os, io, json, asyncio, uuid, pathlib
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL","https://qugtsmqjvxwicfyamlsb.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
JWT_SECRET = os.getenv("JWT_SECRET","munjaz-secret-2025")
JWT_ALGORITHM = "HS256"; JWT_EXPIRE_HOURS = 24

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
openai_client = OpenAI(api_key=OPENAI_API_KEY, timeout=60.0)
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()
executor = ThreadPoolExecutor(max_workers=4)

app = FastAPI(title="Munjaz Enterprise v2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
document_store: dict = {}
ARABIC_RULE = "جميع النصوص باللغة العربية حصرا."

def hash_password(p): return pwd_ctx.hash(p)
def verify_password(plain, hashed): return pwd_ctx.verify(plain, hashed)
def create_token(uid, role):
    exp = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode({"sub": uid, "role": role, "exp": exp}, JWT_SECRET, algorithm=JWT_ALGORITHM)
def decode_token(token):
    try: return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError: raise HTTPException(status_code=401, detail="جلسة منتهية")

async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    payload = decode_token(creds.credentials)
    res = supabase.table("profiles").select("*").eq("id", payload["sub"]).single().execute()
    if not res.data: raise HTTPException(status_code=401, detail="المستخدم غير موجود")
    if not res.data.get("is_active"): raise HTTPException(status_code=403, detail="الحساب معطل")
    return res.data

async def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin": raise HTTPException(status_code=403, detail="للمدراء فقط")
    return user

async def require_manager(user=Depends(get_current_user)):
    if user["role"] not in ("admin","manager"): raise HTTPException(status_code=403, detail="للمشرفين فقط")
    return user

def log_activity(uid, action, entity_type=None, entity_id=None, details=None):
    try: supabase.table("activity_log").insert({"user_id":uid,"action":action,"entity_type":entity_type,"entity_id":entity_id,"details":details or {}}).execute()
    except: pass

@app.get("/")
def serve_login():
    f = pathlib.Path("login.html")
    return FileResponse(str(f)) if f.exists() else {"message":"Munjaz v2.0"}

@app.get("/dashboard")
def serve_dashboard(): return FileResponse("index.html")

@app.get("/landing")
def serve_landing(): return FileResponse("landing.html")

@app.get("/admin")
def serve_admin(): return FileResponse("admin.html")

class LoginReq(BaseModel): email:str; password:str
class ChangePassReq(BaseModel): old_password:str; new_password:str
class ResetPassReq(BaseModel): new_password:str

@app.post("/auth/login")
def login(req: LoginReq):
    res = supabase.table("profiles").select("*").eq("email", req.email.lower().strip()).single().execute()
    if not res.data: raise HTTPException(status_code=401, detail="البريد او كلمة السر غير صحيحة")
    u = res.data
    if not u.get("is_active"): raise HTTPException(status_code=403, detail="الحساب معطل")
    if not u.get("password_hash") or not verify_password(req.password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="البريد او كلمة السر غير صحيحة")
    supabase.table("profiles").update({"last_login": datetime.utcnow().isoformat()}).eq("id", u["id"]).execute()
    log_activity(u["id"], "تسجيل دخول")
    return {"token": create_token(u["id"], u["role"]), "role": u["role"], "name": u["full_name"]}

@app.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return {k:v for k,v in user.items() if k != "password_hash"}

@app.post("/auth/change-password")
async def change_password(req: ChangePassReq, user=Depends(get_current_user)):
    if not verify_password(req.old_password, user["password_hash"]): raise HTTPException(status_code=400, detail="كلمة السر القديمة غير صحيحة")
    supabase.table("profiles").update({"password_hash": hash_password(req.new_password)}).eq("id", user["id"]).execute()
    return {"message":"تم تغيير كلمة السر"}

class CreateUserReq(BaseModel):
    email:str; full_name:str; company:str=""; department:str=""; phone:str=""; role:str="user"; password:str

class UpdateUserReq(BaseModel):
    full_name:Optional[str]=None; company:Optional[str]=None; department:Optional[str]=None; phone:Optional[str]=None; role:Optional[str]=None

@app.get("/users/")
async def list_users(admin=Depends(require_admin)):
    return supabase.table("profiles").select("id,email,full_name,company,department,phone,role,is_active,created_at,last_login").order("created_at",desc=True).execute().data

@app.post("/users/")
async def create_user(req: CreateUserReq, admin=Depends(require_admin)):
    if supabase.table("profiles").select("id").eq("email", req.email.lower()).execute().data:
        raise HTTPException(status_code=400, detail="البريد مسجل مسبقا")
    uid = str(uuid.uuid4())
    supabase.table("profiles").insert({"id":uid,"email":req.email.lower().strip(),"full_name":req.full_name,"company":req.company,"department":req.department,"phone":req.phone,"role":req.role,"password_hash":hash_password(req.password),"is_active":True}).execute()
    log_activity(admin["id"],"انشاء مستخدم","profiles",uid)
    return {"message":"تم انشاء الحساب","id":uid}

@app.put("/users/{uid}")
async def update_user(uid:str, req:UpdateUserReq, admin=Depends(require_admin)):
    d = {k:v for k,v in req.dict().items() if v is not None}
    supabase.table("profiles").update(d).eq("id",uid).execute()
    return {"message":"تم التحديث"}

@app.put("/users/{uid}/reset-password")
async def reset_password(uid:str, req:ResetPassReq, admin=Depends(require_admin)):
    if len(req.new_password) < 6: raise HTTPException(status_code=400, detail="كلمة السر 6 احرف على الاقل")
    supabase.table("profiles").update({"password_hash":hash_password(req.new_password)}).eq("id",uid).execute()
    return {"message":"تم تعيين كلمة سر جديدة"}

@app.put("/users/{uid}/toggle")
async def toggle_user(uid:str, admin=Depends(require_admin)):
    res = supabase.table("profiles").select("is_active,full_name").eq("id",uid).single().execute()
    if not res.data: raise HTTPException(status_code=404, detail="المستخدم غير موجود")
    new_status = not res.data["is_active"]
    supabase.table("profiles").update({"is_active":new_status}).eq("id",uid).execute()
    return {"message":f"تم تفعيل الحساب" if new_status else "تم تعطيل الحساب","is_active":new_status}

@app.delete("/users/{uid}")
async def delete_user(uid:str, admin=Depends(require_admin)):
    supabase.table("profiles").delete().eq("id",uid).execute()
    return {"message":"تم حذف المستخدم"}

class DeptReq(BaseModel): name:str; code:Optional[str]=None; description:str=""; manager_id:Optional[str]=None

@app.get("/departments/")
async def list_departments(user=Depends(get_current_user)):
    return supabase.table("departments").select("*, profiles(full_name)").eq("is_active",True).order("name").execute().data

@app.post("/departments/")
async def create_department(req:DeptReq, admin=Depends(require_admin)):
    supabase.table("departments").insert({**req.dict(),"id":str(uuid.uuid4())}).execute()
    return {"message":"تم انشاء القسم"}

@app.put("/departments/{did}")
async def update_department(did:str, req:DeptReq, admin=Depends(require_admin)):
    supabase.table("departments").update(req.dict()).eq("id",did).execute()
    return {"message":"تم تحديث القسم"}

@app.delete("/departments/{did}")
async def delete_department(did:str, admin=Depends(require_admin)):
    supabase.table("departments").update({"is_active":False}).eq("id",did).execute()
    return {"message":"تم الحذف"}

class EmpCreate(BaseModel):
    employee_number:str; full_name:str; arabic_name:Optional[str]=None
    email:Optional[str]=None; phone:Optional[str]=None; national_id:Optional[str]=None; iqama_number:Optional[str]=None
    nationality:str="سعودي"; department_id:Optional[str]=None; position:str; grade:Optional[str]=None
    employment_type:str="full_time"; status:str="active"
    hire_date:Optional[str]=None; end_date:Optional[str]=None; birth_date:Optional[str]=None
    gender:Optional[str]=None; basic_salary:Optional[float]=None; allowances:float=0
    bank_name:Optional[str]=None; iban:Optional[str]=None; address:Optional[str]=None; city:Optional[str]=None
    emergency_name:Optional[str]=None; emergency_phone:Optional[str]=None; notes:Optional[str]=None

class EmpUpdate(BaseModel):
    full_name:Optional[str]=None; arabic_name:Optional[str]=None
    email:Optional[str]=None; phone:Optional[str]=None; national_id:Optional[str]=None; iqama_number:Optional[str]=None
    nationality:Optional[str]=None; department_id:Optional[str]=None; position:Optional[str]=None; grade:Optional[str]=None
    employment_type:Optional[str]=None; status:Optional[str]=None
    hire_date:Optional[str]=None; end_date:Optional[str]=None; birth_date:Optional[str]=None
    gender:Optional[str]=None; basic_salary:Optional[float]=None; allowances:Optional[float]=None
    bank_name:Optional[str]=None; iban:Optional[str]=None; address:Optional[str]=None; city:Optional[str]=None
    emergency_name:Optional[str]=None; emergency_phone:Optional[str]=None; notes:Optional[str]=None

@app.get("/employees/stats")
async def employee_stats(user=Depends(require_manager)):
    data = supabase.table("employees").select("status,employment_type,nationality,basic_salary,allowances").execute().data or []
    active = [e for e in data if e["status"]=="active"]
    saudis = sum(1 for e in data if e.get("nationality") in ("سعودي","سعودية"))
    total_sal = sum((e.get("basic_salary") or 0)+(e.get("allowances") or 0) for e in active)
    return {"total":len(data),"active":len(active),"inactive":sum(1 for e in data if e["status"]=="inactive"),"on_leave":sum(1 for e in data if e["status"]=="on_leave"),"terminated":sum(1 for e in data if e["status"]=="terminated"),"total_salary":round(total_sal,2),"saudization":round(saudis/len(data)*100) if data else 0,"by_type":{"full_time":sum(1 for e in data if e["employment_type"]=="full_time"),"part_time":sum(1 for e in data if e["employment_type"]=="part_time"),"contract":sum(1 for e in data if e["employment_type"]=="contract"),"intern":sum(1 for e in data if e["employment_type"]=="intern")}}

@app.get("/employees/")
async def list_employees(user=Depends(require_manager), search:str=Query(None), department_id:str=Query(None), status:str=Query(None)):
    q = supabase.table("employees").select("*,departments(name,code)")
    if search: q = q.or_(f"full_name.ilike.%{search}%,employee_number.ilike.%{search}%,position.ilike.%{search}%")
    if department_id: q = q.eq("department_id", department_id)
    if status: q = q.eq("status", status)
    return q.order("created_at", desc=True).execute().data

@app.get("/employees/{eid}")
async def get_employee(eid:str, user=Depends(require_manager)):
    res = supabase.table("employees").select("*,departments(name,code)").eq("id",eid).single().execute()
    if not res.data: raise HTTPException(status_code=404, detail="الموظف غير موجود")
    return res.data

@app.post("/employees/")
async def create_employee(req:EmpCreate, user=Depends(require_manager)):
    if supabase.table("employees").select("id").eq("employee_number",req.employee_number).execute().data:
        raise HTTPException(status_code=400, detail="رقم الموظف مستخدم مسبقا")
    eid = str(uuid.uuid4())
    data = {k:v for k,v in req.dict().items() if v is not None}
    data["id"]=eid; data["created_by"]=user["id"]
    supabase.table("employees").insert(data).execute()
    log_activity(user["id"],"اضافة موظف","employees",eid,{"name":req.full_name})
    return {"message":"تم اضافة الموظف","id":eid}

@app.put("/employees/{eid}")
async def update_employee(eid:str, req:EmpUpdate, user=Depends(require_manager)):
    d = {k:v for k,v in req.dict().items() if v is not None}
    d["updated_at"] = datetime.utcnow().isoformat()
    supabase.table("employees").update(d).eq("id",eid).execute()
    return {"message":"تم تحديث بيانات الموظف"}

@app.delete("/employees/{eid}")
async def delete_employee(eid:str, admin=Depends(require_admin)):
    supabase.table("employees").delete().eq("id",eid).execute()
    return {"message":"تم حذف الموظف"}

class ClientCreate(BaseModel):
    client_code:str; company_name:str; industry:Optional[str]=None
    client_type:str="corporate"; status:str="active"
    contact_name:Optional[str]=None; contact_title:Optional[str]=None; contact_email:Optional[str]=None; contact_phone:Optional[str]=None; contact_phone2:Optional[str]=None
    website:Optional[str]=None; tax_number:Optional[str]=None; cr_number:Optional[str]=None
    address:Optional[str]=None; city:str=""; country:str="المملكة العربية السعودية"
    contract_start:Optional[str]=None; contract_end:Optional[str]=None
    contract_value:Optional[float]=None; credit_limit:Optional[float]=None
    payment_terms:str="30 يوم"; notes:Optional[str]=None

class ClientUpdate(BaseModel):
    company_name:Optional[str]=None; industry:Optional[str]=None; client_type:Optional[str]=None; status:Optional[str]=None
    contact_name:Optional[str]=None; contact_title:Optional[str]=None; contact_email:Optional[str]=None; contact_phone:Optional[str]=None; contact_phone2:Optional[str]=None
    website:Optional[str]=None; tax_number:Optional[str]=None; cr_number:Optional[str]=None
    address:Optional[str]=None; city:Optional[str]=None; country:Optional[str]=None
    contract_start:Optional[str]=None; contract_end:Optional[str]=None
    contract_value:Optional[float]=None; credit_limit:Optional[float]=None; payment_terms:Optional[str]=None; notes:Optional[str]=None

class ContactCreate(BaseModel):
    full_name:str; title:Optional[str]=None; email:Optional[str]=None; phone:Optional[str]=None; department:Optional[str]=None; is_primary:bool=False; notes:Optional[str]=None

@app.get("/clients/stats")
async def client_stats(user=Depends(get_current_user)):
    data = supabase.table("clients").select("status,client_type,contract_value").execute().data or []
    total_val = sum(c.get("contract_value") or 0 for c in data if c["status"]=="active")
    return {"total":len(data),"active":sum(1 for c in data if c["status"]=="active"),"inactive":sum(1 for c in data if c["status"]=="inactive"),"prospect":sum(1 for c in data if c["status"]=="prospect"),"total_contract_value":round(total_val,2),"by_type":{"corporate":sum(1 for c in data if c["client_type"]=="corporate"),"government":sum(1 for c in data if c["client_type"]=="government"),"individual":sum(1 for c in data if c["client_type"]=="individual"),"ngo":sum(1 for c in data if c["client_type"]=="ngo")}}

@app.get("/clients/")
async def list_clients(user=Depends(get_current_user), search:str=Query(None), status:str=Query(None), client_type:str=Query(None)):
    q = supabase.table("clients").select("*")
    if search: q = q.or_(f"company_name.ilike.%{search}%,client_code.ilike.%{search}%,contact_name.ilike.%{search}%")
    if status: q = q.eq("status",status)
    if client_type: q = q.eq("client_type",client_type)
    return q.order("created_at",desc=True).execute().data

@app.get("/clients/{cid}")
async def get_client(cid:str, user=Depends(get_current_user)):
    res = supabase.table("clients").select("*").eq("id",cid).single().execute()
    if not res.data: raise HTTPException(status_code=404, detail="العميل غير موجود")
    contacts = supabase.table("client_contacts").select("*").eq("client_id",cid).execute()
    return {**res.data,"contacts":contacts.data}

@app.post("/clients/")
async def create_client(req:ClientCreate, user=Depends(require_manager)):
    if supabase.table("clients").select("id").eq("client_code",req.client_code).execute().data:
        raise HTTPException(status_code=400, detail="كود العميل مستخدم مسبقا")
    cid = str(uuid.uuid4())
    data = {k:v for k,v in req.dict().items() if v is not None}
    data["id"]=cid; data["created_by"]=user["id"]
    supabase.table("clients").insert(data).execute()
    log_activity(user["id"],"اضافة عميل","clients",cid,{"name":req.company_name})
    return {"message":"تم اضافة العميل","id":cid}

@app.put("/clients/{cid}")
async def update_client(cid:str, req:ClientUpdate, user=Depends(require_manager)):
    d = {k:v for k,v in req.dict().items() if v is not None}
    d["updated_at"]=datetime.utcnow().isoformat()
    supabase.table("clients").update(d).eq("id",cid).execute()
    return {"message":"تم تحديث بيانات العميل"}

@app.delete("/clients/{cid}")
async def delete_client(cid:str, admin=Depends(require_admin)):
    supabase.table("clients").delete().eq("id",cid).execute()
    return {"message":"تم حذف العميل"}

@app.get("/clients/{cid}/contacts")
async def get_contacts(cid:str, user=Depends(get_current_user)):
    return supabase.table("client_contacts").select("*").eq("client_id",cid).execute().data

@app.post("/clients/{cid}/contacts")
async def add_contact(cid:str, req:ContactCreate, user=Depends(require_manager)):
    supabase.table("client_contacts").insert({**req.dict(),"id":str(uuid.uuid4()),"client_id":cid}).execute()
    return {"message":"تم اضافة جهة التواصل"}

@app.delete("/clients/{cid}/contacts/{contact_id}")
async def delete_contact(cid:str, contact_id:str, user=Depends(require_manager)):
    supabase.table("client_contacts").delete().eq("id",contact_id).eq("client_id",cid).execute()
    return {"message":"تم الحذف"}

class DiscCreate(BaseModel):
    title:str; content:str; summary:Optional[str]=None; category:str="general"; importance:str="normal"
    target_roles:List[str]=["user","manager","admin"]; is_published:bool=False; expires_at:Optional[str]=None

class DiscUpdate(BaseModel):
    title:Optional[str]=None; content:Optional[str]=None; summary:Optional[str]=None
    category:Optional[str]=None; importance:Optional[str]=None; target_roles:Optional[List[str]]=None
    is_published:Optional[bool]=None; expires_at:Optional[str]=None

@app.get("/disclosures/")
async def list_disclosures(user=Depends(get_current_user), published_only:bool=Query(False), category:str=Query(None)):
    q = supabase.table("disclosures").select("*,profiles(full_name)")
    if published_only: q = q.eq("is_published",True)
    if category: q = q.eq("category",category)
    return q.order("created_at",desc=True).execute().data

@app.get("/disclosures/{did}")
async def get_disclosure(did:str, user=Depends(get_current_user)):
    res = supabase.table("disclosures").select("*,profiles(full_name)").eq("id",did).single().execute()
    if not res.data: raise HTTPException(status_code=404, detail="الافصاح غير موجود")
    try:
        supabase.table("disclosure_views").insert({"disclosure_id":did,"user_id":user["id"]}).execute()
        supabase.table("disclosures").update({"views_count":(res.data.get("views_count",0)+1)}).eq("id",did).execute()
    except: pass
    return res.data

@app.post("/disclosures/")
async def create_disclosure(req:DiscCreate, user=Depends(require_manager)):
    did = str(uuid.uuid4())
    data = req.dict(); data["id"]=did; data["created_by"]=user["id"]
    if req.is_published: data["published_at"]=datetime.utcnow().isoformat()
    supabase.table("disclosures").insert(data).execute()
    log_activity(user["id"],"انشاء افصاح","disclosures",did,{"title":req.title})
    return {"message":"تم انشاء الافصاح","id":did}

@app.put("/disclosures/{did}")
async def update_disclosure(did:str, req:DiscUpdate, user=Depends(require_manager)):
    d = {k:v for k,v in req.dict().items() if v is not None}
    d["updated_at"]=datetime.utcnow().isoformat()
    supabase.table("disclosures").update(d).eq("id",did).execute()
    return {"message":"تم تحديث الافصاح"}

@app.put("/disclosures/{did}/publish")
async def publish_disclosure(did:str, user=Depends(require_manager)):
    supabase.table("disclosures").update({"is_published":True,"published_at":datetime.utcnow().isoformat()}).eq("id",did).execute()
    return {"message":"تم نشر الافصاح"}

@app.put("/disclosures/{did}/unpublish")
async def unpublish_disclosure(did:str, user=Depends(require_manager)):
    supabase.table("disclosures").update({"is_published":False}).eq("id",did).execute()
    return {"message":"تم الغاء النشر"}

@app.delete("/disclosures/{did}")
async def delete_disclosure(did:str, admin=Depends(require_admin)):
    supabase.table("disclosures").delete().eq("id",did).execute()
    return {"message":"تم الحذف"}

@app.get("/stats/overview")
async def overview_stats(admin=Depends(require_admin)):
    users = supabase.table("profiles").select("id,is_active,role").execute().data or []
    emps = supabase.table("employees").select("id,status").execute().data or []
    clients = supabase.table("clients").select("id,status").execute().data or []
    discs = supabase.table("disclosures").select("id,is_published").execute().data or []
    analyses = supabase.table("analyses").select("id,verdict,score").execute().data or []
    scores = [a["score"] for a in analyses if a.get("score") is not None]
    recent = supabase.table("activity_log").select("action,entity_type,created_at,profiles(full_name)").order("created_at",desc=True).limit(10).execute().data
    return {"users":{"total":len(users),"active":sum(1 for u in users if u["is_active"]),"admins":sum(1 for u in users if u["role"]=="admin")},"employees":{"total":len(emps),"active":sum(1 for e in emps if e["status"]=="active"),"on_leave":sum(1 for e in emps if e["status"]=="on_leave")},"clients":{"total":len(clients),"active":sum(1 for c in clients if c["status"]=="active"),"prospect":sum(1 for c in clients if c["status"]=="prospect")},"disclosures":{"total":len(discs),"published":sum(1 for d in discs if d["is_published"])},"analyses":{"total":len(analyses),"avg_score":round(sum(scores)/len(scores)) if scores else 0,"proceed":sum(1 for a in analyses if a.get("verdict")=="PROCEED")},"recent_activity":recent}

@app.get("/analyses/")
async def list_analyses(admin=Depends(require_admin)):
    return supabase.table("analyses").select("id,filename,pages,verdict,score,created_at,profiles(full_name,company)").order("created_at",desc=True).execute().data

@app.delete("/analyses/{aid}")
async def delete_analysis(aid:str, admin=Depends(require_admin)):
    supabase.table("analyses").delete().eq("id",aid).execute()
    return {"message":"تم الحذف"}



# ═══════════════════════════════════════════════════════════════
# 10 AI AGENTS — منجز v3.1 — نظام استشاري متكامل
# ═══════════════════════════════════════════════════════════════
ARABIC_RULE = "قاعدة صارمة: جميع النصوص باللغة العربية حصراً."

# ─── Tool Definitions ────────────────────────────────────────

DOC_TOOLS=[{"type":"function","function":{"name":"document_agent","description":"استخرج بيانات المناقصة كاملة","parameters":{"type":"object","properties":{"title":{"type":"string"},"description":{"type":"string"},"requirements":{"type":"array","items":{"type":"object","properties":{"req_id":{"type":"string"},"title":{"type":"string"},"description":{"type":"string"},"is_mandatory":{"type":"boolean"},"category":{"type":"string","enum":["technical","financial","legal","administrative","other"]}},"required":["req_id","title","description","is_mandatory","category"]}},"deadlines":{"type":"array","items":{"type":"object","properties":{"event":{"type":"string"},"date_text":{"type":"string"},"is_critical":{"type":"boolean"}},"required":["event","date_text","is_critical"]}},"documents_required":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"is_mandatory":{"type":"boolean"}},"required":["name","is_mandatory"]}},"estimated_value":{"type":"string"},"duration":{"type":"string"},"location":{"type":"string"},"scope_of_work":{"type":"string"}},"required":["title","description","requirements","deadlines","documents_required"]}}}]

LEGAL_TOOLS=[{"type":"function","function":{"name":"legal_agent","description":"تحليل الشروط القانونية وبنود العقد","parameters":{"type":"object","properties":{"contract_terms":{"type":"array","items":{"type":"object","properties":{"term":{"type":"string"},"risk_level":{"type":"string","enum":["high","medium","low"]},"notes":{"type":"string"}},"required":["term","risk_level","notes"]}},"penalties":{"type":"array","items":{"type":"string"}},"termination_clauses":{"type":"string"},"legal_risks":{"type":"array","items":{"type":"string"}},"legal_score":{"type":"integer","description":"0=خطر قانوني عالي, 100=آمن تماماً"},"ambiguous_clauses":{"type":"array","items":{"type":"string"}},"summary":{"type":"string"}},"required":["contract_terms","legal_risks","legal_score","summary"]}}}]

FIN_TOOLS=[{"type":"function","function":{"name":"financial_agent","description":"تحليل الجانب المالي والربحية","parameters":{"type":"object","properties":{"estimated_budget":{"type":"string"},"payment_terms":{"type":"string"},"financial_guarantees":{"type":"array","items":{"type":"string"}},"cost_risks":{"type":"array","items":{"type":"object","properties":{"item":{"type":"string"},"impact":{"type":"string","enum":["high","medium","low"]}},"required":["item","impact"]}},"profitability_assessment":{"type":"string","enum":["مربح جداً","مربح","متعادل","غير مربح","مجهول"]},"profit_margin_estimate":{"type":"string","description":"نسبة هامش الربح المتوقعة"},"financial_score":{"type":"integer","description":"0=خسارة محققة, 100=ربح ممتاز"},"recommendations":{"type":"array","items":{"type":"string"}},"summary":{"type":"string"}},"required":["profitability_assessment","financial_score","summary"]}}}]

TECH_TOOLS=[{"type":"function","function":{"name":"technical_agent","description":"تحليل المتطلبات الفنية والتحديات التقنية","parameters":{"type":"object","properties":{"technical_requirements":{"type":"array","items":{"type":"object","properties":{"req":{"type":"string"},"complexity":{"type":"string","enum":["عالية","متوسطة","منخفضة"]},"feasible":{"type":"boolean"}},"required":["req","complexity","feasible"]}},"technologies_needed":{"type":"array","items":{"type":"string"}},"challenges":{"type":"array","items":{"type":"string"}},"technical_score":{"type":"integer","description":"0=تحديات كبيرة, 100=قابلية تنفيذ عالية"},"resource_requirements":{"type":"string"},"summary":{"type":"string"}},"required":["technical_requirements","technical_score","summary"]}}}]

RISK_TOOLS=[{"type":"function","function":{"name":"risk_agent","description":"تحليل المخاطر الشاملة مع الإفصاحات كقواعد مخاطر","parameters":{"type":"object","properties":{"risks":{"type":"array","items":{"type":"object","properties":{"risk_id":{"type":"string"},"title":{"type":"string"},"description":{"type":"string"},"severity":{"type":"string","enum":["حرج","عالي","متوسط","منخفض"]},"source":{"type":"string","enum":["document","disclosure","client","market"]},"mitigation":{"type":"string"}},"required":["risk_id","title","description","severity","source","mitigation"]}},"alerts":{"type":"array","items":{"type":"object","properties":{"alert_id":{"type":"string"},"message":{"type":"string"},"level":{"type":"string","enum":["خطر","تحذير","معلومة"]},"source":{"type":"string"}},"required":["alert_id","message","level","source"]}},"risk_score":{"type":"integer","description":"0=خطر شديد, 100=آمن تماماً"},"overall_risk_level":{"type":"string","enum":["حرج","عالي","متوسط","منخفض"]},"disclosure_violations":{"type":"array","items":{"type":"string"},"description":"الإفصاحات التي تنتهكها المناقصة"},"summary":{"type":"string"}},"required":["risks","alerts","risk_score","overall_risk_level","summary"]}}}]

CLIENT_TOOLS=[{"type":"function","function":{"name":"client_agent","description":"تقييم توافق المناقصة مع بيانات العميل واستراتيجيته","parameters":{"type":"object","properties":{"fit_score":{"type":"integer","description":"0=غير مناسب إطلاقاً, 100=مناسب تماماً"},"recommendation":{"type":"string","enum":["مناسب جداً","مناسب","محايد","غير مناسب"]},"alignment_with_strategy":{"type":"string","description":"مدى توافق المناقصة مع استراتيجية العميل"},"client_strengths":{"type":"array","items":{"type":"string"}},"client_weaknesses":{"type":"array","items":{"type":"string"}},"reason":{"type":"string"},"customized_advice":{"type":"string"},"risk_tolerance_match":{"type":"boolean","description":"هل تتوافق المناقصة مع مستوى المخاطرة للعميل"}},"required":["fit_score","recommendation","reason","customized_advice","risk_tolerance_match"]}}}]

STRATEGY_TOOLS=[{"type":"function","function":{"name":"strategy_agent","description":"اقتراح استراتيجية دخول المناقصة وسعر العطاء","parameters":{"type":"object","properties":{"bid_decision":{"type":"string","enum":["ادخل بقوة","ادخل بحذر","ادخل مشروط","لا تدخل"]},"bid_decision_reason":{"type":"string"},"suggested_price":{"type":"string","description":"السعر المقترح أو النطاق السعري"},"price_rationale":{"type":"string","description":"مبرر السعر المقترح"},"approach":{"type":"string","enum":["Aggressive","Balanced","Safe","No Bid"]},"approach_description":{"type":"string","description":"وصف طريقة الدخول المقترحة"},"win_probability":{"type":"string","description":"نسبة الفوز المتوقعة مثل 65%"},"competitive_advantages":{"type":"array","items":{"type":"string"}},"key_conditions":{"type":"array","items":{"type":"string"},"description":"الشروط التي يجب تحقيقها قبل الدخول"},"negotiation_points":{"type":"array","items":{"type":"string"},"description":"نقاط يجب التفاوض عليها"},"timeline_recommendation":{"type":"string"}},"required":["bid_decision","bid_decision_reason","suggested_price","approach","approach_description","win_probability","competitive_advantages","key_conditions"]}}}]

ASSIGN_TOOLS=[{"type":"function","function":{"name":"assignment_agent","description":"توزيع مهام التحليل والتنفيذ على الأقسام","parameters":{"type":"object","properties":{"assignments":{"type":"array","items":{"type":"object","properties":{"department":{"type":"string"},"task":{"type":"string"},"priority":{"type":"string","enum":["عاجل","مهم","عادي"]},"deadline":{"type":"string"},"deliverable":{"type":"string"}},"required":["department","task","priority"]}},"primary_department":{"type":"string"},"coordination_notes":{"type":"string"},"escalation_needed":{"type":"boolean"}},"required":["assignments","primary_department"]}}}]

HISTORY_TOOLS=[{"type":"function","function":{"name":"history_agent","description":"أرشفة المناقصة بشكل ذكي للرجوع إليها مستقبلاً","parameters":{"type":"object","properties":{"archive_summary":{"type":"string"},"key_points":{"type":"array","items":{"type":"string"}},"lessons_learned":{"type":"array","items":{"type":"string"}},"tags":{"type":"array","items":{"type":"string"}},"similar_tenders_advice":{"type":"string"},"future_reference":{"type":"string","description":"ملاحظات للمناقصات المستقبلية المشابهة"}},"required":["archive_summary","key_points","tags"]}}}]

SUMMARY_TOOLS=[{"type":"function","function":{"name":"summary_agent","description":"القرار النهائي الاستراتيجي الشامل","parameters":{"type":"object","properties":{"decision":{"type":"string","enum":["PROCEED","CLARIFY","RISK","REJECT"]},"decision_ar":{"type":"string"},"overall_score":{"type":"integer","description":"الدرجة الكلية 0-100"},"verdict_color":{"type":"string","enum":["green","yellow","red"]},"executive_summary":{"type":"string","description":"ملخص تنفيذي شامل في 3-4 جمل"},"key_reasons":{"type":"array","items":{"type":"string"}},"action_items":{"type":"array","items":{"type":"object","properties":{"action":{"type":"string"},"responsible":{"type":"string"},"priority":{"type":"string","enum":["فوري","قريب","عادي"]},"deadline":{"type":"string"}},"required":["action","responsible","priority"]}},"questions_for_client":{"type":"array","items":{"type":"object","properties":{"number":{"type":"integer"},"question":{"type":"string"},"priority":{"type":"string","enum":["عاجل","مهم","عادي"]}},"required":["number","question","priority"]}},"strategic_advice":{"type":"string","description":"النصيحة الاستراتيجية النهائية للإدارة"}},"required":["decision","decision_ar","overall_score","verdict_color","executive_summary","key_reasons","action_items","questions_for_client","strategic_advice"]}}}]


# ─── Agent Runner ─────────────────────────────────────────────
def _call_tool(tools, messages, tool_name):
    r = openai_client.chat.completions.create(
        model="gpt-4o", max_tokens=4000,
        tools=tools,
        tool_choice={"type":"function","function":{"name":tool_name}},
        messages=messages
    )
    msg = r.choices[0].message
    if msg.tool_calls:
        try: return json.loads(msg.tool_calls[0].function.arguments)
        except: return {}
    return {}


def _sys(role): return {"role":"system","content":role+" "+ARABIC_RULE}
def _user(content): return {"role":"user","content":content[:14000]}
def _ctx(d): return json.dumps(d, ensure_ascii=False)[:3000]


def run_document_agent(text):
    return _call_tool(DOC_TOOLS,[
        _sys("أنت محلل وثائق مناقصات خبير بخبرة 20 عاماً في القطاعين الحكومي والخاص. استخرج كل المعلومات بدقة عالية. ركز على الأرقام والتواريخ والشروط الجوهرية. لا تُهمل أي تفصيل."),
        _user("استخرج كل بيانات هذه المناقصة:\n\n"+text)
    ],"document_agent")

def run_legal_agent(text, doc):
    return _call_tool(LEGAL_TOOLS,[
        _sys("أنت محامٍ متخصص في عقود المناقصات السعودية والخليجية بخبرة 15 عاماً. حلل كل بند قانوني بعين ناقدة. ابحث عن الفخاخ القانونية والشروط الجزائية والبنود الغامضة التي قد تضر بالمتعاقد. كن صريحاً في التقييم."),
        _user("حلل الشروط القانونية. ركز على البنود الجزائية والغامضة.\n\nبيانات المناقصة:\n"+_ctx(doc)+"\n\nالنص الكامل:\n"+text[:8000])
    ],"legal_agent")

def run_financial_agent(text, doc):
    return _call_tool(FIN_TOOLS,[
        _sys("أنت محلل مالي متمرس متخصص في تسعير وتقييم المناقصات. احسب هامش الربح الحقيقي مع احتساب المخاطر والتكاليف الخفية. قيّم ضمانات الدفع ومخاطر التأخر. أعطِ تقديراً دقيقاً للربحية الصافية."),
        _user("حلل الجانب المالي وقدّر الربحية.\n\n"+_ctx(doc)+"\n\n"+text[:8000])
    ],"financial_agent")

def run_technical_agent(text, doc):
    return _call_tool(TECH_TOOLS,[
        _sys("أنت مهندس أول متخصص في تقييم المشاريع والمناقصات التقنية. قيّم كل متطلب تقني بموضوعية. حدد التحديات الحقيقية ومتطلبات الموارد. كن واقعياً في تقييم الجدوى التنفيذية."),
        _user("حلل المتطلبات التقنية وقيّم صعوبة التنفيذ.\n\n"+_ctx(doc)+"\n\n"+text[:8000])
    ],"technical_agent")

def run_risk_agent(text, doc, legal, fin, tech, disclosures_text):
    all_ctx = _ctx({"doc":doc,"legal":legal,"fin":fin,"tech":tech})
    disc_ctx = f"\n\n=== قواعد المخاطر من الإفصاحات (يجب مقارنة المناقصة بها) ===\n{disclosures_text}" if disclosures_text else ""
    return _call_tool(RISK_TOOLS,[
        _sys("انت محلل مخاطر محترف. قارن المناقصة مع قواعد المخاطر المستخرجة من الإفصاحات. أصدر تنبيهات دقيقة."),
        _user("حلل المخاطر الشاملة وقارن مع الإفصاحات:\n"+all_ctx+disc_ctx+"\n\n"+text[:6000])
    ],"risk_agent")

def run_client_agent(text, doc, risk, client_data):
    client_ctx = _ctx(client_data) if client_data else "لا توجد بيانات عميل محددة"
    return _call_tool(CLIENT_TOOLS,[
        _sys("انت مستشار أعمال متخصص في تخصيص قرارات المناقصات حسب بيانات العميل واستراتيجيته."),
        _user(f"قيّم توافق هذه المناقصة مع بيانات العميل الآتية:\n\nبيانات العميل:\n{client_ctx}\n\nالمناقصة:\n{_ctx(doc)}\n\nالمخاطر:\n{_ctx(risk)}")
    ],"client_agent")

def run_strategy_agent(doc, legal, fin, tech, risk, client, client_data):
    client_ctx = _ctx(client_data) if client_data else "بدون عميل محدد"
    all_analysis = _ctx({"doc":doc,"legal":legal,"fin":fin,"tech":tech,"risk":risk,"client":client})
    return _call_tool(STRATEGY_TOOLS,[
        _sys("أنت مستشار استراتيجي رفيع المستوى متخصص في استراتيجيات تسعير والفوز بالمناقصات. اقترح استراتيجية دخول مدروسة مع سعر تنافسي حقيقي. اربط قرارك بتحليل المنافسين المحتملين وظروف السوق. نسبة الفوز يجب أن تكون واقعية ومبنية على التحليل."),
        _user(f"بناءً على التحليل الكامل، اقترح استراتيجية دخول المناقصة:\n\nبيانات العميل:\n{client_ctx}\n\nالتحليل الكامل:\n{all_analysis}")
    ],"strategy_agent")

def run_assignment_agent(doc, strategy, depts_list):
    depts_ctx = ", ".join(depts_list) if depts_list else "الأقسام العامة"
    return _call_tool(ASSIGN_TOOLS,[
        _sys("انت مدير تشغيل محترف. وزّع المهام بشكل عملي وواضح."),
        _user(f"وزّع مهام التحليل والتنفيذ على الأقسام المتاحة:\n\nالأقسام: {depts_ctx}\n\nالمناقصة:\n{_ctx(doc)}\n\nالاستراتيجية:\n{_ctx(strategy)}")
    ],"assignment_agent")

def run_history_agent(all_results):
    return _call_tool(HISTORY_TOOLS,[
        _sys("انت مدير أرشيف ذكي. وثّق المناقصة بشكل يفيد المستقبل."),
        _user("أرشف هذه المناقصة بشكل شامل:\n"+_ctx(all_results))
    ],"history_agent")

def run_summary_agent(all_results, client_data):
    client_ctx = _ctx(client_data) if client_data else "بدون عميل"
    return _call_tool(SUMMARY_TOOLS,[
        _sys("أنت كبير المستشارين الاستراتيجيين. بناءً على تحليل 9 agents متخصصين، أصدر قراراً نهائياً حاسماً وموثوقاً. الملخص التنفيذي يجب أن يكون مقنعاً للإدارة العليا. اجمع كل التحليلات في رأي واحد واضح لا لبس فيه."),
        _user(f"بناءً على تحليل 9 Agents، أصدر القرار النهائي الاستراتيجي:\n\nبيانات العميل:\n{client_ctx}\n\nجميع التحليلات:\n{_ctx(all_results)}")
    ],"summary_agent")


# ─── Tenders Endpoints ────────────────────────────────────────
@app.get("/tenders/")
async def list_tenders(
    user=Depends(get_current_user),
    search:str=Query(None), status:str=Query(None),
    verdict:str=Query(None), client_id:str=Query(None),
    user_id:str=Query(None)
):
    q=supabase.table("tenders").select("id,title,filename,status,verdict,verdict_ar,overall_score,risk_score,fit_score,created_at,completed_at,user_id,profiles(full_name,company),clients(company_name),departments(name)")
    # Admin sees ALL tenders always
    if user["role"] == "user":
        q=q.eq("user_id",user["id"])
    elif user_id:
        q=q.eq("user_id",user_id)
    if search: q=q.ilike("title",f"%{search}%")
    if status: q=q.eq("status",status)
    if verdict: q=q.eq("verdict",verdict)
    if client_id: q=q.eq("client_id",client_id)
    return q.order("created_at",desc=True).execute().data

@app.get("/tenders/stats")
async def tender_stats(user=Depends(get_current_user)):
    q=supabase.table("tenders").select("id,status,verdict,overall_score,risk_score,fit_score")
    if user["role"] not in ("admin","manager"): q=q.eq("user_id",user["id"])
    data=q.execute().data or []
    scores=[t["overall_score"] for t in data if t.get("overall_score")]
    return {
        "total":len(data),
        "by_status":{"جديدة":sum(1 for t in data if t["status"]=="جديدة"),"قيد التحليل":sum(1 for t in data if t["status"]=="قيد التحليل"),"مكتملة":sum(1 for t in data if t["status"]=="مكتملة"),"مرفوضة":sum(1 for t in data if t["status"]=="مرفوضة")},
        "by_verdict":{"PROCEED":sum(1 for t in data if t.get("verdict")=="PROCEED"),"CLARIFY":sum(1 for t in data if t.get("verdict")=="CLARIFY"),"RISK":sum(1 for t in data if t.get("verdict")=="RISK"),"REJECT":sum(1 for t in data if t.get("verdict")=="REJECT")},
        "avg_score":round(sum(scores)/len(scores)) if scores else 0,
        "avg_risk":round(sum(t["risk_score"] for t in data if t.get("risk_score"))/len(data)) if data else 0,
        "avg_fit":round(sum(t["fit_score"] for t in data if t.get("fit_score"))/len(data)) if data else 0,
    }

@app.get("/tenders/{tid}")
async def get_tender(tid:str, user=Depends(get_current_user)):
    res=supabase.table("tenders").select("*,profiles(full_name,company),clients(company_name,industry,client_type,contact_name),departments(name)").eq("id",tid).single().execute()
    if not res.data: raise HTTPException(status_code=404,detail="المناقصة غير موجودة")
    t=res.data
    if user["role"] not in ("admin","manager") and t.get("user_id")!=user["id"]:
        raise HTTPException(status_code=403,detail="غير مصرح")
    return t

@app.delete("/tenders/{tid}")
async def delete_tender(tid:str, admin=Depends(require_admin)):
    supabase.table("tenders").delete().eq("id",tid).execute()
    return {"message":"تم حذف المناقصة"}


# ── Tender Assignments (Employee) ─────────────────────
class TenderAssignRequest(BaseModel):
    tender_id: str
    employee_ids: List[str]
    notes: Optional[str] = None

@app.get("/tenders/{tid}/suggest-employees")
async def suggest_employees_for_tender(tid:str, user=Depends(require_manager)):
    """الذكاء الاصطناعي يقترح الموظفين المناسبين للمناقصة"""
    # جلب بيانات المناقصة
    tender_res = supabase.table("tenders").select("title,description,assignments,technical_analysis,final_decision").eq("id",tid).single().execute()
    if not tender_res.data:
        raise HTTPException(status_code=404, detail="المناقصة غير موجودة")
    tender = tender_res.data

    # جلب جميع الموظفين النشطين مع أقسامهم
    emps_res = supabase.table("employees").select("id,full_name,position,grade,department_id,nationality,employment_type,departments(name,code)").eq("status","active").execute()
    employees = emps_res.data or []
    if not employees:
        return {"suggestions": [], "message": "لا يوجد موظفون نشطون"}

    # جلب التكليفات الحالية لكل موظف (عبء العمل)
    workload = {}
    for emp in employees:
        cnt = supabase.table("tender_assignments").select("id", count="exact").eq("employee_id", emp["id"]).execute()
        workload[emp["id"]] = cnt.count or 0

    # بناء قائمة الموظفين للـ AI
    emp_lines = []
    for e in employees:
        dept_name = (e.get("departments") or {}).get("name", "—")
        line = f"- ID:{e['id']} | الاسم:{e['full_name']} | المسمى:{e['position']} | القسم:{dept_name} | عبء العمل:{workload.get(e['id'],0)} مناقصة"
        emp_lines.append(line)
    emp_list = "\n".join(emp_lines)

    tender_title = tender.get("title", "")
    tender_desc = tender.get("description", "")
    tender_assign = json.dumps(tender.get("assignments", {}), ensure_ascii=False)[:800]
    tender_tech = json.dumps(tender.get("technical_analysis", {}), ensure_ascii=False)[:400]
    tender_ctx = f"عنوان المناقصة: {tender_title}\nالوصف: {tender_desc}\nتوزيع الأقسام: {tender_assign}\nالمتطلبات التقنية: {tender_tech}"

    prompt = "أنت مدير موارد بشرية ذكي. بناءً على بيانات المناقصة وقائمة الموظفين، اقترح أفضل 3-5 موظفين للعمل على هذه المناقصة.\n\n"
    prompt += f"المناقصة:\n{tender_ctx}\n\nالموظفون المتاحون:\n{emp_list}\n\n"
    prompt += """قواعد الاختيار:
- اختر الموظفين الأنسب حسب المسمى الوظيفي والقسم
- افضّل من لديهم عبء عمل أقل
- أعطِ سبباً واضحاً لكل اختيار
- أجب بالعربية فقط

أجب بصيغة JSON فقط:
{
  "suggestions": [
    {
      "employee_id": "ID هنا",
      "employee_name": "الاسم",
      "role_in_tender": "دوره في المناقصة",
      "reason": "سبب الاختيار",
      "priority": "رئيسي أو داعم",
      "match_score": 85
    }
  ],
  "assignment_notes": "ملاحظات عامة للإدارة"
}"""


    loop = asyncio.get_event_loop()
    def _call_ai():
        r = openai_client.chat.completions.create(
            model="gpt-4o", max_tokens=2000,
            messages=[{"role":"user","content":prompt}],
            response_format={"type":"json_object"}
        )
        return json.loads(r.choices[0].message.content)

    result = await asyncio.wait_for(loop.run_in_executor(executor, _call_ai), timeout=30)

    # أضف بيانات الموظف الكاملة لكل اقتراح
    emp_map = {e["id"]: e for e in employees}
    for s in result.get("suggestions", []):
        emp = emp_map.get(s.get("employee_id"), {})
        s["department"] = emp.get("departments", {}).get("name", "—") if emp else "—"
        s["position"] = emp.get("position", "—")
        s["current_workload"] = workload.get(s.get("employee_id"), 0)

    return result


@app.post("/tenders/{tid}/assign-employees")
async def assign_employees_to_tender(tid:str, req:TenderAssignRequest, user=Depends(require_manager)):
    # حذف التكليفات القديمة
    supabase.table("tender_assignments").delete().eq("tender_id",tid).execute()
    # إضافة التكليفات الجديدة
    records = [{"tender_id":tid,"employee_id":eid,"assigned_by":user["id"],"notes":req.notes} for eid in req.employee_ids]
    if records:
        supabase.table("tender_assignments").insert(records).execute()
    log_activity(user["id"],"تكليف موظفين","tenders",tid,{"count":len(req.employee_ids)})
    return {"message":f"تم تكليف {len(req.employee_ids)} موظف"}

@app.get("/tenders/{tid}/assignments")
async def get_tender_assignments(tid:str, user=Depends(get_current_user)):
    res = supabase.table("tender_assignments").select("*,employees(full_name,position,departments(name))").eq("tender_id",tid).execute()
    return res.data

@app.get("/employees/{eid}/tenders")
async def get_employee_tenders(eid:str, user=Depends(require_manager)):
    res = supabase.table("tender_assignments").select("*,tenders(id,title,status,verdict,overall_score,created_at,clients(company_name))").eq("employee_id",eid).execute()
    return [r["tenders"] for r in (res.data or []) if r.get("tenders")]

@app.get("/departments/{did}/workload")
async def get_department_workload(did:str, user=Depends(require_manager)):
    # جلب موظفي القسم
    emps = supabase.table("employees").select("id,full_name,position").eq("department_id",did).eq("status","active").execute().data or []
    workload = []
    for emp in emps:
        tenders = supabase.table("tender_assignments").select("tender_id,tenders(id,title,status,verdict,overall_score)").eq("employee_id",emp["id"]).execute().data or []
        workload.append({**emp,"assigned_tenders":len(tenders),"tenders":[t["tenders"] for t in tenders if t.get("tenders")]})
    return workload

@app.get("/stats/workload")
async def workload_stats(admin=Depends(require_admin)):
    depts = supabase.table("departments").select("id,name").eq("is_active",True).execute().data or []
    result = []
    for dept in depts:
        emps = supabase.table("employees").select("id").eq("department_id",dept["id"]).eq("status","active").execute().data or []
        emp_ids = [e["id"] for e in emps]
        assigned = 0
        if emp_ids:
            for eid in emp_ids:
                cnt = supabase.table("tender_assignments").select("id",count="exact").eq("employee_id",eid).execute()
                assigned += cnt.count or 0
        result.append({"department":dept["name"],"employees":len(emps),"assigned_tenders":assigned})
    return result


# ─── Gatekeeper Agent ─────────────────────────────────────
GATE_TOOLS=[{"type":"function","function":{"name":"gatekeeper_agent","description":"فحص ما إذا كان الملف وثيقة مناقصة حقيقية","parameters":{"type":"object","properties":{"is_tender":{"type":"boolean"},"confidence":{"type":"integer"},"document_type":{"type":"string"},"rejection_reason":{"type":"string"},"tender_indicators":{"type":"array","items":{"type":"string"}}},"required":["is_tender","confidence","document_type","rejection_reason","tender_indicators"]}}}]

def run_gatekeeper(text):
    return _call_tool(GATE_TOOLS,[
        {"role":"system","content":"""أنت حارس بوابة متخصص في تحديد وثائق المناقصات.
مهمتك: هل هذا الملف وثيقة مناقصة أو عطاء أو طرح أو مشتريات؟

علامات المناقصة الحقيقية:
- شروط وأحكام للتقديم
- متطلبات فنية أو مالية لتقديم عروض
- مواعيد تقديم العروض
- معايير تقييم العروض
- جهة طارحة تطلب عروضاً

ليست مناقصات (ارفض فوراً):
- قوائم طعام / منيو
- سير ذاتية / CVs
- تقارير مالية عادية
- مقالات وأبحاث
- عقود توظيف / فواتير
- أي وثيقة لا تطلب عروض أسعار

كن صارماً جداً — أي شك = رفض. """+ARABIC_RULE},
        {"role":"user","content":"افحص هذه الوثيقة:\n\n"+text[:5000]}
    ], "gatekeeper_agent")


# ─── Main Analyze Endpoint (Gatekeeper + 10 Agents) ──────
@app.post("/analyze/")
async def analyze(
    file: UploadFile = File(...),
    client_id: str = None,
    user=Depends(require_admin)
):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="ملفات PDF فقط — يرجى رفع ملف بصيغة PDF")

    contents = await file.read()
    text = ""; page_count = 0
    with pdfplumber.open(io.BytesIO(contents)) as pdf:
        page_count = len(pdf.pages)
        for page in pdf.pages: text += page.extract_text() or ""
    if not text.strip():
        raise HTTPException(status_code=400, detail="تعذّر استخراج النص — تأكد أن الملف يحتوي على نص قابل للقراءة")

    # ═══ Gatekeeper Check ═══
    loop = asyncio.get_event_loop()
    gate = await asyncio.wait_for(
        loop.run_in_executor(executor, run_gatekeeper, text), timeout=30
    )

    if not gate.get("is_tender", False) or gate.get("confidence", 0) < 60:
        doc_type = gate.get("document_type", "وثيقة غير معروفة")
        reason   = gate.get("rejection_reason", "الملف لا يحتوي على مؤشرات مناقصة")
        raise HTTPException(
            status_code=422,
            detail={
                "error": "not_a_tender",
                "title": "هذا الملف ليس وثيقة مناقصة",
                "document_type": doc_type,
                "reason": reason,
                "confidence": gate.get("confidence", 0),
                "message": f"تم اكتشاف الملف كـ '{doc_type}'. {reason}. يرجى رفع وثيقة مناقصة أو عطاء أو طرح رسمي."
            }
        )

    # حفظ أولي بحالة "قيد التحليل"
    tid = str(uuid.uuid4())
    supabase.table("tenders").insert({
        "id":tid, "user_id":user["id"],
        "client_id":client_id if client_id else None,
        "filename":file.filename, "pages":page_count,
        "status":"قيد التحليل", "title":file.filename
    }).execute()

    # جلب بيانات مساعدة
    client_data = None
    if client_id:
        cr = supabase.table("clients").select("*").eq("id", client_id).single().execute()
        if cr.data: client_data = cr.data

    disclosures_text = ""

    # جلب الأقسام
    depts_res = supabase.table("departments").select("name").eq("is_active",True).execute()
    depts_list = [d["name"] for d in (depts_res.data or [])]


    # ═══ Agent 1: Document ═══
    doc_result = await asyncio.wait_for(
        loop.run_in_executor(executor, run_document_agent, text), timeout=60
    )

    # ═══ Agents 2, 3, 4 بالتوازي ═══
    legal_f = loop.run_in_executor(executor, run_legal_agent, text, doc_result)
    fin_f   = loop.run_in_executor(executor, run_financial_agent, text, doc_result)
    tech_f  = loop.run_in_executor(executor, run_technical_agent, text, doc_result)
    legal_result, fin_result, tech_result = await asyncio.wait_for(
        asyncio.gather(legal_f, fin_f, tech_f), timeout=120
    )

    # ═══ Agent 5: Risk (يستخدم الإفصاحات) ═══
    risk_result = await asyncio.wait_for(
        loop.run_in_executor(executor, run_risk_agent, text, doc_result, legal_result, fin_result, tech_result, disclosures_text),
        timeout=60
    )

    # ═══ Agent 6: Client ═══
    client_result = await asyncio.wait_for(
        loop.run_in_executor(executor, run_client_agent, text, doc_result, risk_result, client_data),
        timeout=60
    )

    # ═══ Agent 7: Strategy ═══ (الإضافة القوية)
    strategy_result = await asyncio.wait_for(
        loop.run_in_executor(executor, run_strategy_agent, doc_result, legal_result, fin_result, tech_result, risk_result, client_result, client_data),
        timeout=60
    )

    # ═══ Agent 8: Assignment ═══
    assign_result = await asyncio.wait_for(
        loop.run_in_executor(executor, run_assignment_agent, doc_result, strategy_result, depts_list),
        timeout=60
    )

    # ═══ Agent 9: History ═══
    all_for_history = {
        "document":doc_result, "legal":legal_result, "financial":fin_result,
        "technical":tech_result, "risk":risk_result, "client":client_result,
        "strategy":strategy_result, "assignments":assign_result
    }
    history_result = await asyncio.wait_for(
        loop.run_in_executor(executor, run_history_agent, all_for_history), timeout=60
    )

    # ═══ Agent 10: Summary ═══
    all_for_summary = {**all_for_history, "history":history_result}
    summary_result = await asyncio.wait_for(
        loop.run_in_executor(executor, run_summary_agent, all_for_summary, client_data), timeout=60
    )

    # حساب الدرجات
    risk_score    = risk_result.get("risk_score", 50)
    fit_score     = client_result.get("fit_score", 50)
    overall_score = summary_result.get("overall_score", 50)
    verdict       = summary_result.get("decision", "CLARIFY")
    verdict_ar    = summary_result.get("decision_ar", "طلب توضيحات")
    alerts        = risk_result.get("alerts", [])

    # رفع الملف
    file_url = None
    try:
        fp = f"{user['id']}/{uuid.uuid4()}/{file.filename}"
        supabase.storage.from_("pdfs").upload(fp, contents, {"content-type":"application/pdf"})
        file_url = f"{SUPABASE_URL}/storage/v1/object/pdfs/{fp}"
    except: pass

    # تحديث قاعدة البيانات
    title       = doc_result.get("title", file.filename)
    description = doc_result.get("description", "")

    dept_id = None
    primary_dept = assign_result.get("primary_department","")
    if primary_dept and depts_res.data:
        for d in depts_res.data:
            if d["name"] in primary_dept or primary_dept in d["name"]:
                dr = supabase.table("departments").select("id").eq("name",d["name"]).single().execute()
                if dr.data: dept_id = dr.data["id"]; break

    supabase.table("tenders").update({
        "title":title, "description":description, "file_url":file_url,
        "status":"مكتملة", "department_id":dept_id,
        "document_summary":doc_result, "legal_analysis":legal_result,
        "financial_analysis":fin_result, "technical_analysis":tech_result,
        "risk_analysis":risk_result, "client_evaluation":client_result,
        "strategy_analysis":strategy_result,
        "assignments":assign_result, "history_summary":history_result,
        "final_decision":summary_result,
        "risk_score":risk_score, "fit_score":fit_score, "overall_score":overall_score,
        "verdict":verdict, "verdict_ar":verdict_ar, "alerts":alerts,
        "completed_at":datetime.utcnow().isoformat(),
        "updated_at":datetime.utcnow().isoformat()
    }).eq("id",tid).execute()

    log_activity(user["id"], "رفع مناقصة", "tenders", tid, {"title":title,"verdict":verdict,"score":overall_score})

    sid = str(uuid.uuid4())
    document_store[sid] = {
        "text":text, "analysis":all_for_summary,
        "tender_id":tid, "client_data":client_data
    }

    return {
        "session_id":sid, "tender_id":tid, "filename":file.filename, "pages":page_count,
        "title":title, "description":description,
        "document_summary":doc_result, "legal_analysis":legal_result,
        "financial_analysis":fin_result, "technical_analysis":tech_result,
        "risk_analysis":risk_result, "client_evaluation":client_result,
        "strategy_analysis":strategy_result,
        "assignments":assign_result, "history_summary":history_result,
        "final_decision":summary_result,
        "risk_score":risk_score, "fit_score":fit_score, "overall_score":overall_score,
        "verdict":verdict, "verdict_ar":verdict_ar, "alerts":alerts
    }


class ChatReq(BaseModel): session_id:str; question:str

@app.post("/chat/")
async def chat(req:ChatReq, user=Depends(get_current_user)):
    stored = document_store.get(req.session_id)
    if not stored: raise HTTPException(status_code=404, detail="انتهت الجلسة، أعد رفع الملف")
    analysis_ctx = json.dumps(stored["analysis"], ensure_ascii=False)[:5000]
    client_ctx = json.dumps(stored.get("client_data"), ensure_ascii=False) if stored.get("client_data") else "لا يوجد عميل"
    sys_prompt = f"""أنت مستشار مناقصات استراتيجي متخصص. لديك المعلومات التالية:

=== نص المناقصة ===
{stored["text"][:15000]}

=== التحليل الكامل (10 Agents) ===
{analysis_ctx}

=== بيانات العميل ===
{client_ctx}

قواعد: اجب بالعربية دائماً. اربط إجابتك ببيانات المناقصة والعميل. كن محدداً وعملياً."""

    messages = [{"role":"system","content":sys_prompt}, {"role":"user","content":req.question}]
    loop = asyncio.get_event_loop()
    r = await loop.run_in_executor(executor, lambda: openai_client.chat.completions.create(
        model="gpt-4o", max_tokens=2000, messages=messages
    ))
    return {"answer":r.choices[0].message.content}
