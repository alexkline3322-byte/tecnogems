---
inclusion: always
---

# TecnoGems — سياق المشروع

> **ملف steering حيّ** — يُحدَّث بعد كل PR لتعكس حالة المشروع الراهنة.
> لا تحذف الأقسام الثابتة (نظرة عامة، بنية، قرارات معمارية) حتى لو صارت بديهية.

---

## 1) نظرة عامة

**TecnoGems** متجر شحن ألعاب إلكتروني (gaming topup store) موجَّه للسوق العربي الخليجي.

- **المنصة:** Flask 3 + SQLite + RQ (Redis queue اختياري)
- **اللغة:** Python 3.11+
- **اللغات المدعومة في الواجهة:** عربي / إنجليزي (Flask-Babel)
- **المزوِّدون:** G2Bulk (سيرفر 1) + Shop2Topup (سيرفر 2)
- **المستودع:** `alexkline3322-byte/tecnogems`
- **الفرع الأساسي:** `main`

## 2) البنية على القرص

المستودع حالياً يحتوي على مجلد فرعي واحد هو الكود الفعلي:

```
tecnogems/
├── src/
│   └── tecnogems_V49_STABLE/        ← كل الكود هنا
│       ├── app.py                   ~2580 سطر  — routes + security + logic
│       ├── database.py              ~1625 سطر  — SQLite schema + queries
│       ├── providers.py              ~353 سطر  — G2Bulk + Shop2Topup
│       ├── tasks.py                  ~230 سطر  — RQ + email + supplier sanitise
│       ├── sync_products.py          ~360 سطر  — catalog sync
│       ├── featured_games.py          ~90 سطر
│       ├── wsgi.py                    ~35 سطر
│       ├── worker_rq.py               ~22 سطر
│       ├── requirements.txt
│       ├── Procfile                  Heroku entrypoint
│       ├── .env.example              متغيرات البيئة
│       ├── .gitignore
│       ├── routes/__init__.py        (placeholder — blueprint split مستقبلاً)
│       ├── templates/                22 قالب Jinja2 (+ admin/)
│       ├── static/css/               9 ملفات CSS (v35 → v44 neon)
│       ├── static/js/                app.js + app.min.js
│       ├── static/img/               صور الألعاب + icons
│       ├── translations/             ar/ + en/ (LC_MESSAGES)
│       ├── tools/gen_posters.py      توليد صور المنتجات
│       └── V*.md / V*.txt            سجلات التغيير لكل إصدار
│
├── tecnogems_V49_STABLE(1).zip      ← أرشيف قديم، يجب حذفه
└── .kiro/steering/                   ← هذا الملف
```

**ملاحظة هيكل:** الكود في `src/tecnogems_V49_STABLE/` وليس في الجذر.
تنظيف الهيكل (نقل الكود إلى الجذر + حذف الـ zip) ضمن البنود المتبقية.

## 3) تقنيات رئيسية

- **Web:** Flask 3.0.3, Flask-WTF, Flask-Limiter, Flask-Babel
- **DB:** SQLite (عبر `sqlite3` القياسي، لا ORM)
- **Auth:** session-based + Werkzeug password hashing + Authlib (Google OAuth)
- **Queue:** RQ 1.16 + Redis (اختياري؛ يوجد fallback داخلي بـ threading)
- **Server:** Gunicorn (gthread × 4)
- **Images:** Pillow 10.4
- **Mail:** SMTP (Flask-Mail)

## 4) الإصلاحات المُنجزة ✅

| الإصدار | PR | ما الذي تم | الملف المرجعي |
|--------|----|-----------|--------------|
| **V50** | [#1](https://github.com/alexkline3322-byte/tecnogems/pull/1) | 14 إصلاح حرج/عالٍ (Critical + High) | `V50_SECURITY_FIXES.md` |
| **V50.2** | [#2](https://github.com/alexkline3322-byte/tecnogems/pull/2) | 22 إصلاح متوسط/منخفض (Medium + Low) | `V50_2_SECURITY_FIXES.md` |

**أبرز ما طُبِّق أمنياً:**
- `secrets.token_urlsafe` لـ `order_code` و `deposit_code`
- Rate-limit على auth + admin routes (Flask-Limiter + Redis backend)
- حدود طول على كل مدخلات المستخدم (email/password/name/phone/proof/player_id)
- `safe_next_url` مقوَّى ضد open-redirect
- Upload path نُقل خارج `static/` إلى `data/uploads/`
- CSP محكَم + HSTS 2 سنة + COOP/CORP/XPCDP
- CSRF SSL-strict في الإنتاج + Origin/Referer guard على `/api/*`
- Audit logs على كل admin actions (`log.warning("ADMIN_..."))`
- `current_user()` يفحص `active=1`
- Supplier errors تُنظَّف قبل التخزين (`_sanitise_supplier_note` في `tasks.py`)
- `.gitignore` يحمي `.secret_key`, `*.sqlite`, `*.log`, `rq.db`
- Session 7 أيام (كان 14)

## 5) البنود المتبقية ⏳

مرتَّبة **حسب الأولوية**:

### أولوية عالية

- [ ] **A. تنظيف هيكل المستودع** *(PR صغير — 5 دقائق)*
  - نقل محتويات `src/tecnogems_V49_STABLE/*` إلى جذر المستودع
  - حذف `tecnogems_V49_STABLE(1).zip`
  - تحديث `.gitignore` + `Procfile` + `README.md` إن لزم

- [ ] **B. 2FA لحسابات الأدمن** *(PR متوسط)*
  - `pyotp` + عمود `users.totp_secret`
  - `/admin/2fa/setup` مع QR code + 10 backup codes
  - حارس `require_2fa_admin` على كل admin routes

- [ ] **C. Tests + CI** *(PR كبير — لكن الأعلى قيمة)*
  - `tests/` مع pytest: auth, orders, wallet, admin, security
  - `.github/workflows/ci.yml`: pytest + bandit + pip-audit

### أولوية متوسطة

- [ ] **D. Sentry + Structured Logging + Audit Table**
  - `sentry-sdk[flask]` + `SENTRY_DSN`
  - JSON logs عبر `python-json-logger`
  - جدول `audit_log(id, ts, actor_id, action, target, old, new, ip, ua)`

- [ ] **E. ترحيل SQLite → PostgreSQL**
  - استبدال `sqlite3` بـ `psycopg2` أو SQLAlchemy
  - Alembic migrations
  - تحديث `DATABASE_URL` في `.env`

### أولوية منخفضة (لكن ضرورية)

- [ ] **F. إزالة `style="…"` inline**
  - 22 قالب يحتاج تمشيط
  - نقل إلى classes في `static/css/`
  - تشديد CSP: `style-src 'self'` (حذف `unsafe-inline`)

- [ ] **G. WAF + نسخ احتياطية**
  - `backup.sh` cron → S3 / مخزن خارجي
  - Cloudflare rules (معظمه خارج الكود)
  - `DEPLOYMENT.md`

### الختامي

- [ ] **H. Release v51+ نهائي**
  - tag `v51.0-stable` بعد اكتمال A-G
  - GitHub Release مع CHANGELOG موحَّد
  - تنظيف ملفات `V*.md` القديمة إلى `docs/history/`

## 6) القرارات المعمارية المُتخذة 🏗️

| القرار | السبب |
|-------|-------|
| **إبقاء SQLite مؤقتاً** | المشروع لم يصل حجم يستدعي PG. التأجيل يقلّل مخاطر ترحيل مبكّر. |
| **Rate-limit عبر Redis اختيارياً** | Redis موجود أصلاً لـ RQ. إعادة استخدامه مجاني عملياً. |
| **Audit في logs فقط حالياً** | DB audit table مؤجَّل لبند D. |
| **إبقاء GET /logout للتوافق** | روابط قديمة في الإيميلات + bookmarks. يُسجَّل كـ deprecated. |
| **حذف PDF من uploads** | PDFs يمكن أن تحوي JS/XSS payloads. PNG/JPG/WEBP فقط. |
| **CSP لا يزال يسمح `style-src unsafe-inline`** | بسبب inline styles في القوالب. بند F سيرفع هذا. |
| **`FLASK_ENV=production` يفعّل كل السلوكيات الصارمة** | قرار مركزي: debugger off, CSRF strict, إلخ. |

## 7) متغيرات البيئة المهمة

```bash
# أمنية (إلزامية في الإنتاج)
SECRET_KEY=<secrets.token_urlsafe(48)>
FLASK_ENV=production
BASE_URL=https://tecnogems.com

# حدود
MAX_DEPOSIT_USD=10000
MAX_ADMIN_BALANCE=1000000
SESSION_LIFETIME_DAYS=7

# بنية تحتية (اختيارية)
REDIS_URL=redis://localhost:6379/0   # للـ RQ + Flask-Limiter

# مزوِّدون
G2BULK_API_KEY=...
SHOP2TOPUP_API_KEY=...

# OAuth
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://tecnogems.com/auth/google/callback

# Mail
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=...
MAIL_PASSWORD=...
```

## 8) تشغيل المشروع محلياً

```bash
cd src/tecnogems_V49_STABLE
cp .env.example .env
# حرِّر .env وأضف SECRET_KEY

pip install -r requirements.txt

# تطوير
FLASK_ENV=development python app.py

# إنتاج (Gunicorn)
gunicorn -k gthread -w 2 --threads 4 -b 0.0.0.0:8000 wsgi:app
```

## 9) موقع الملفات الحساسة 📍

| المحتوى | الملف / الموقع |
|--------|----------------|
| Security policies (CSP, HSTS, rate-limits) | `app.py` — ابحث عن `V50` أو `V50.2` |
| Admin routes | `app.py` — `admin_*` functions |
| DB schema | `database.py` — بداية الملف (`CREATE TABLE`) |
| Supplier sanitization | `tasks.py` — `_sanitise_supplier_note` |
| Upload validation | `app.py` — `_PROOF_MAGIC`, `ALLOWED_UPLOAD_EXTS` |
| `safe_next_url` | `app.py` — ابحث عن الاسم |
| Templates base (CSP nonce) | `templates/base.html` |
| Robots.txt (حجب /admin و /api) | `static/robots.txt` |

## 10) آخر تحديث 📌

- **Commit:** `c13ee94` (PR #2 merged 2026-05-11)
- **الحالة:** V50.2 مكتمل. الكود في الإنتاج جاهز أمنياً للبنود الـ 36 المُصنَّفة.
- **التالي:** البند **A** (تنظيف الهيكل) أو **B** (2FA للأدمن).
