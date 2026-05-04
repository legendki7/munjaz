-- ═══════════════════════════════════════════════════════════════
-- منجز — نظام مؤسسي متكامل | Schema كامل
-- شغّل هذا في Supabase SQL Editor
-- ═══════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────
-- 1. جدول الملفات الشخصية (المستخدمون)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS profiles (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  full_name     TEXT NOT NULL,
  company       TEXT DEFAULT '',
  role          TEXT DEFAULT 'user' CHECK (role IN ('admin','manager','user')),
  department    TEXT DEFAULT '',
  phone         TEXT DEFAULT '',
  avatar_url    TEXT,
  password_hash TEXT,
  is_active     BOOLEAN DEFAULT TRUE,
  last_login    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
);

-- كلمة سر الأدمن المؤقتة: Munjaz@2025
INSERT INTO profiles (id, email, full_name, role, password_hash, is_active)
VALUES (
  gen_random_uuid(),
  'admin@munjaz.ai',
  'مدير النظام',
  'admin',
  '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TiGX4M4UoBJMOW/vSNqFvqMU2fKO',
  TRUE
) ON CONFLICT (email) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  role = 'admin';

-- ─────────────────────────────────────────
-- 2. جدول الأقسام
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS departments (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  code        TEXT UNIQUE,
  manager_id  UUID REFERENCES profiles(id) ON DELETE SET NULL,
  description TEXT DEFAULT '',
  is_active   BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ DEFAULT now()
);

INSERT INTO departments (name, code) VALUES
  ('الإدارة العامة',    'MGMT'),
  ('تقنية المعلومات',   'IT'),
  ('المالية',           'FIN'),
  ('الموارد البشرية',   'HR'),
  ('المبيعات',          'SALES'),
  ('العمليات',          'OPS'),
  ('القانوني',          'LEGAL'),
  ('التسويق',           'MKT')
ON CONFLICT (code) DO NOTHING;

-- ─────────────────────────────────────────
-- 3. جدول الموظفين
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS employees (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  employee_number TEXT UNIQUE NOT NULL,
  full_name       TEXT NOT NULL,
  arabic_name     TEXT,
  email           TEXT UNIQUE,
  phone           TEXT,
  national_id     TEXT,
  iqama_number    TEXT,
  nationality     TEXT DEFAULT 'سعودي',
  department_id   UUID REFERENCES departments(id) ON DELETE SET NULL,
  position        TEXT NOT NULL,
  grade           TEXT,
  employment_type TEXT DEFAULT 'full_time' CHECK (employment_type IN ('full_time','part_time','contract','intern')),
  status          TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','on_leave','terminated')),
  hire_date       DATE,
  end_date        DATE,
  birth_date      DATE,
  gender          TEXT CHECK (gender IN ('male','female')),
  basic_salary    NUMERIC(12,2),
  allowances      NUMERIC(12,2) DEFAULT 0,
  bank_name       TEXT,
  iban            TEXT,
  address         TEXT,
  city            TEXT,
  emergency_name  TEXT,
  emergency_phone TEXT,
  notes           TEXT,
  avatar_url      TEXT,
  created_by      UUID REFERENCES profiles(id),
  created_at      TIMESTAMPTZ DEFAULT now(),
  updated_at      TIMESTAMPTZ DEFAULT now()
);

-- ─────────────────────────────────────────
-- 4. جدول العملاء
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clients (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_code     TEXT UNIQUE NOT NULL,
  company_name    TEXT NOT NULL,
  industry        TEXT,
  client_type     TEXT DEFAULT 'corporate' CHECK (client_type IN ('corporate','government','individual','ngo')),
  status          TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','prospect','suspended')),
  contact_name    TEXT,
  contact_title   TEXT,
  contact_email   TEXT,
  contact_phone   TEXT,
  contact_phone2  TEXT,
  website         TEXT,
  tax_number      TEXT,
  cr_number       TEXT,
  address         TEXT,
  city            TEXT DEFAULT '',
  country         TEXT DEFAULT 'المملكة العربية السعودية',
  contract_start  DATE,
  contract_end    DATE,
  contract_value  NUMERIC(14,2),
  credit_limit    NUMERIC(14,2),
  payment_terms   TEXT DEFAULT '30 يوم',
  notes           TEXT,
  tags            TEXT[],
  created_by      UUID REFERENCES profiles(id),
  created_at      TIMESTAMPTZ DEFAULT now(),
  updated_at      TIMESTAMPTZ DEFAULT now()
);

-- ─────────────────────────────────────────
-- 5. جدول جهات التواصل للعملاء
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS client_contacts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id   UUID REFERENCES clients(id) ON DELETE CASCADE,
  full_name   TEXT NOT NULL,
  title       TEXT,
  email       TEXT,
  phone       TEXT,
  department  TEXT,
  is_primary  BOOLEAN DEFAULT FALSE,
  notes       TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- ─────────────────────────────────────────
-- 6. جدول الإفصاحات والإعلانات
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS disclosures (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title         TEXT NOT NULL,
  content       TEXT NOT NULL,
  summary       TEXT,
  category      TEXT DEFAULT 'general' CHECK (category IN (
    'financial','operational','legal','hr','technical','strategic','general','urgent'
  )),
  importance    TEXT DEFAULT 'normal' CHECK (importance IN ('critical','high','normal','low')),
  target_roles  TEXT[] DEFAULT ARRAY['user','manager','admin'],
  is_published  BOOLEAN DEFAULT FALSE,
  published_at  TIMESTAMPTZ,
  expires_at    TIMESTAMPTZ,
  attachments   JSONB DEFAULT '[]',
  views_count   INTEGER DEFAULT 0,
  created_by    UUID REFERENCES profiles(id),
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
);

-- ─────────────────────────────────────────
-- 7. جدول مشاهدات الإفصاحات
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS disclosure_views (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  disclosure_id  UUID REFERENCES disclosures(id) ON DELETE CASCADE,
  user_id        UUID REFERENCES profiles(id) ON DELETE CASCADE,
  viewed_at      TIMESTAMPTZ DEFAULT now(),
  UNIQUE(disclosure_id, user_id)
);

-- ─────────────────────────────────────────
-- 8. جدول سجل النشاطات
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES profiles(id) ON DELETE SET NULL,
  action      TEXT NOT NULL,
  entity_type TEXT,
  entity_id   UUID,
  details     JSONB DEFAULT '{}',
  ip_address  TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- ─────────────────────────────────────────
-- 9. جدول تحليلات المناقصات (محدّث)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analyses (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID REFERENCES profiles(id) ON DELETE SET NULL,
  client_id           UUID REFERENCES clients(id) ON DELETE SET NULL,
  filename            TEXT,
  pages               INTEGER,
  file_url            TEXT,
  analyzer_results    JSONB DEFAULT '{}',
  compliance_results  JSONB DEFAULT '{}',
  qa_results          JSONB DEFAULT '{}',
  decision            JSONB DEFAULT '{}',
  verdict             TEXT,
  score               INTEGER,
  notes               TEXT,
  created_at          TIMESTAMPTZ DEFAULT now()
);

-- ─────────────────────────────────────────
-- Indexes للأداء
-- ─────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_employees_dept    ON employees(department_id);
CREATE INDEX IF NOT EXISTS idx_employees_status  ON employees(status);
CREATE INDEX IF NOT EXISTS idx_clients_status    ON clients(status);
CREATE INDEX IF NOT EXISTS idx_disclosures_pub   ON disclosures(is_published, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_user     ON analyses(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_user     ON activity_log(user_id, created_at DESC);

-- ─────────────────────────────────────────
-- Row Level Security (اختياري)
-- ─────────────────────────────────────────
-- ALTER TABLE employees ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE clients   ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE disclosures ENABLE ROW LEVEL SECURITY;
