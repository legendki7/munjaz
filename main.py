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
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
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

ANALYZER_TOOLS=[{"type":"function","function":{"name":"extract_requirements","description":"استخرج متطلبات المناقصة","parameters":{"type":"object","properties":{"requirements":{"type":"array","items":{"type":"object","properties":{"req_id":{"type":"string"},"title":{"type":"string"},"description":{"type":"string"},"is_mandatory":{"type":"boolean"},"category":{"type":"string","enum":["technical","financial","legal","administrative","other"]}},"required":["req_id","title","description","is_mandatory","category"]}},"total_count":{"type":"integer"}},"required":["requirements","total_count"]}}},{"type":"function","function":{"name":"extract_deadlines","description":"استخرج المواعيد","parameters":{"type":"object","properties":{"deadlines":{"type":"array","items":{"type":"object","properties":{"deadline_id":{"type":"string"},"event":{"type":"string"},"date_text":{"type":"string"},"is_critical":{"type":"boolean"}},"required":["deadline_id","event","date_text","is_critical"]}}},"required":["deadlines"]}}},{"type":"function","function":{"name":"extract_documents","description":"استخرج المستندات","parameters":{"type":"object","properties":{"documents":{"type":"array","items":{"type":"object","properties":{"doc_id":{"type":"string"},"name":{"type":"string"},"is_mandatory":{"type":"boolean"},"notes":{"type":"string"}},"required":["doc_id","name","is_mandatory"]}},"total_count":{"type":"integer"}},"required":["documents","total_count"]}}}]
COMPLIANCE_TOOLS=[{"type":"function","function":{"name":"check_gaps","description":"افحص الثغرات","parameters":{"type":"object","properties":{"gaps":{"type":"array","items":{"type":"object","properties":{"gap_id":{"type":"string"},"title":{"type":"string"},"description":{"type":"string"},"severity":{"type":"string","enum":["critical","major","minor"]}},"required":["gap_id","title","description","severity"]}},"completeness_score":{"type":"number"},"overall_assessment":{"type":"string"}},"required":["gaps","completeness_score","overall_assessment"]}}},{"type":"function","function":{"name":"check_ambiguities","description":"افحص الغموض","parameters":{"type":"object","properties":{"ambiguities":{"type":"array","items":{"type":"object","properties":{"amb_id":{"type":"string"},"clause":{"type":"string"},"issue":{"type":"string"},"impact":{"type":"string","enum":["high","medium","low"]}},"required":["amb_id","clause","issue","impact"]}}},"required":["ambiguities"]}}},{"type":"function","function":{"name":"check_conflicts","description":"افحص التعارضات","parameters":{"type":"object","properties":{"conflicts":{"type":"array","items":{"type":"object","properties":{"conflict_id":{"type":"string"},"clause_a":{"type":"string"},"clause_b":{"type":"string"},"description":{"type":"string"},"risk_level":{"type":"string","enum":["high","medium","low"]},"suggested_resolution":{"type":"string"}},"required":["conflict_id","clause_a","clause_b","description","risk_level","suggested_resolution"]}},"overall_risk":{"type":"string","enum":["high","medium","low","clear"]}},"required":["conflicts","overall_risk"]}}}]
QA_TOOLS=[{"type":"function","function":{"name":"generate_formal_questions","description":"انشئ اسئلة استيضاح","parameters":{"type":"object","properties":{"questions":{"type":"array","items":{"type":"object","properties":{"number":{"type":"integer"},"category":{"type":"string","enum":["technical","financial","legal","administrative","timeline"]},"subject":{"type":"string"},"question_ar":{"type":"string"},"based_on":{"type":"string"},"priority":{"type":"string","enum":["urgent","important","normal"]}},"required":["number","category","subject","question_ar","priority"]}},"cover_letter_ar":{"type":"string"}},"required":["questions","cover_letter_ar"]}}}]

def _run_agent(tools,messages,tool_names):
    results={}
    for tn in tool_names:
        r=openai_client.chat.completions.create(model="gpt-4o-mini",max_tokens=2000,tools=tools,tool_choice={"type":"function","function":{"name":tn}},messages=messages)
        msg=r.choices[0].message
        if msg.tool_calls:
            tc=msg.tool_calls[0]; args=json.loads(tc.function.arguments); results[tn]=args
            messages.append({"role":"assistant","content":None,"tool_calls":[{"id":tc.id,"type":"function","function":{"name":tn,"arguments":tc.function.arguments}}]})
            messages.append({"role":"tool","tool_call_id":tc.id,"content":json.dumps(args)})
    return results

def run_analyzer(text):
    return _run_agent(ANALYZER_TOOLS,[{"role":"system","content":"انت محلل وثائق مناقصات. "+ARABIC_RULE},{"role":"user","content":"حلل هذه الوثيقة:\n\n"+text[:12000]}],["extract_requirements","extract_deadlines","extract_documents"])

def run_compliance(text,analyzer):
    ctx=json.dumps(analyzer,ensure_ascii=False)
    return _run_agent(COMPLIANCE_TOOLS,[{"role":"system","content":"انت محلل امتثال. "+ARABIC_RULE},{"role":"user","content":"راجع:\n"+ctx+"\n\n"+text[:10000]}],["check_gaps","check_ambiguities","check_conflicts"])

def run_qa(text,analyzer,compliance):
    ctx=json.dumps({**analyzer,**compliance},ensure_ascii=False)
    r=openai_client.chat.completions.create(model="gpt-4o-mini",max_tokens=3000,tools=QA_TOOLS,tool_choice={"type":"function","function":{"name":"generate_formal_questions"}},messages=[{"role":"system","content":"انت خبير مناقصات. "+ARABIC_RULE},{"role":"user","content":"انشئ اسئلة:\n"+ctx+"\n\n"+text[:6000]}])
    msg=r.choices[0].message
    return json.loads(msg.tool_calls[0].function.arguments) if msg.tool_calls else {}

def compute_decision(analyzer,compliance,qa):
    reqs=analyzer.get("extract_requirements",{}).get("requirements",[])
    deadlines=analyzer.get("extract_deadlines",{}).get("deadlines",[])
    docs=analyzer.get("extract_documents",{}).get("documents",[])
    gaps=compliance.get("check_gaps",{}).get("gaps",[])
    ambs=compliance.get("check_ambiguities",{}).get("ambiguities",[])
    conflicts=compliance.get("check_conflicts",{}).get("conflicts",[])
    completeness=compliance.get("check_gaps",{}).get("completeness_score",50)
    critical_gaps=[g for g in gaps if g.get("severity")=="critical"]
    high_conf=[c for c in conflicts if c.get("risk_level")=="high"]
    urgent_qs=[q for q in qa.get("questions",[]) if q.get("priority")=="urgent"]
    score=100; issues=[]
    if critical_gaps: score-=len(critical_gaps)*15; issues.append(f"{len(critical_gaps)} نقص حرج")
    if high_conf: score-=len(high_conf)*20; issues.append(f"{len(high_conf)} تعارض عالي الخطورة")
    if len(ambs)>3: score-=10; issues.append(f"{len(ambs)} بند غامض")
    if completeness<60: score-=15; issues.append(f"اكتمال {completeness:.0f}% فقط")
    score=max(0,min(100,score))
    if score>=75 and not critical_gaps and not high_conf: verdict,verdict_ar,color,exp="PROCEED","المضي قدما","green","المستند مكتمل."
    elif score>=50: verdict,verdict_ar,color,exp="CLARIFY","طلب توضيحات","yellow","توجد نقاط تحتاج توضيحا."
    else: verdict,verdict_ar,color,exp="RISK","مخاطر عالية","red","المستند يحتوي على تعارضات او نقص حرج."
    return {"verdict":verdict,"verdict_ar":verdict_ar,"verdict_color":color,"score":round(score),"explanation":exp,"issues":issues,"stats":{"requirements":len(reqs),"mandatory_reqs":len([r for r in reqs if r.get("is_mandatory")]),"deadlines":len(deadlines),"critical_deadlines":len([d for d in deadlines if d.get("is_critical")]),"documents":len(docs),"mandatory_docs":len([d for d in docs if d.get("is_mandatory")]),"gaps":len(gaps),"critical_gaps":len(critical_gaps),"ambiguities":len(ambs),"conflicts":len(conflicts),"urgent_questions":len(urgent_qs),"completeness":round(completeness)}}

@app.post("/analyze/")
async def analyze(file: UploadFile = File(...), user=Depends(get_current_user)):
    if not file.filename.lower().endswith(".pdf"): raise HTTPException(status_code=400, detail="ملفات PDF فقط")
    contents=await file.read(); text=""; page_count=0
    with pdfplumber.open(io.BytesIO(contents)) as pdf:
        page_count=len(pdf.pages)
        for page in pdf.pages: text+=page.extract_text() or ""
    if not text.strip(): raise HTTPException(status_code=400, detail="تعذر استخراج النص")
    loop=asyncio.get_event_loop()
    analyzer_results=await asyncio.wait_for(loop.run_in_executor(executor,run_analyzer,text),timeout=90)
    cf=loop.run_in_executor(executor,run_compliance,text,analyzer_results)
    qf=loop.run_in_executor(executor,run_qa,text,analyzer_results,{})
    compliance_results,qa_results=await asyncio.wait_for(asyncio.gather(cf,qf),timeout=90)
    decision=compute_decision(analyzer_results,compliance_results,qa_results)
    file_url=None
    try:
        fp=f"{user['id']}/{uuid.uuid4()}/{file.filename}"
        supabase.storage.from_("pdfs").upload(fp,contents,{"content-type":"application/pdf"})
        file_url=f"{SUPABASE_URL}/storage/v1/object/pdfs/{fp}"
    except: pass
    aid=str(uuid.uuid4())
    supabase.table("analyses").insert({"id":aid,"user_id":user["id"],"filename":file.filename,"pages":page_count,"file_url":file_url,"analyzer_results":analyzer_results,"compliance_results":compliance_results,"qa_results":qa_results,"decision":decision,"verdict":decision["verdict"],"score":decision["score"]}).execute()
    sid=str(uuid.uuid4())
    document_store[sid]={"text":text,"analysis":{"analyzer":analyzer_results,"compliance":compliance_results,"qa":qa_results,"decision":decision}}
    return {"session_id":sid,"analysis_id":aid,"filename":file.filename,"pages":page_count,"analyzer":analyzer_results,"compliance":compliance_results,"qa":qa_results,"decision":decision}

class ChatReq(BaseModel): session_id:str; question:str

@app.post("/chat/")
async def chat(req:ChatReq, user=Depends(get_current_user)):
    stored=document_store.get(req.session_id)
    if not stored: raise HTTPException(status_code=404, detail="انتهت الجلسة")
    ctx=f"=== الوثيقة ===\n{stored['text'][:20000]}\n\n=== التحليل ===\n{json.dumps(stored['analysis'],ensure_ascii=False)[:4000]}"
    messages=[{"role":"system","content":"انت مساعد مناقصات. اجب بالعربية دائما.\n\n"+ctx},{"role":"user","content":req.question}]
    loop=asyncio.get_event_loop()
    r=await loop.run_in_executor(executor,lambda:openai_client.chat.completions.create(model="gpt-4o-mini",max_tokens=1200,messages=messages))
    return {"answer":r.choices[0].message.content}
