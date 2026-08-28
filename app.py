# -*- coding: utf-8 -*-
"""
教务管理系统 - Flask Web Application
榆中县职业技术学校：订书发书 / 排课 / 调课(看课补助) / 超课时统计 / 夜自习 / 加班管理费
"""
import os
import io
import re
import json
import sys
import time
import hmac
import math
import hashlib
import threading
import calendar
import random
import uuid
from datetime import datetime, date, timedelta

# fnOS: 将 py_packages 加入 Python 路径（install_callback 安装到此目录）
_fn_pkg = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'py_packages')
if os.path.exists(_fn_pkg):
    sys.path.insert(0, _fn_pkg)

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, send_file, jsonify, session, Response, g)
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ── App配置 ──
app = Flask(__name__)
# 数据库路径：fnOS 上使用 TRIM_PKGVAR（持久化数据目录），否则用默认 instance/
trim_pkgvar = os.environ.get('TRIM_PKGVAR', '')
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if trim_pkgvar:
    db_path = os.path.join(trim_pkgvar, 'edu_admin.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    UPLOAD_FOLDER = os.path.join(trim_pkgvar, 'uploads')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edu_admin.db'
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'instance', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 365 * 24 * 3600  # 静态文件缓存1年
# 会话 Cookie 安全（内网 HTTP 不能开 Secure，否则登录态丢失）
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

db = SQLAlchemy(app)

# SQLite 并发优化：WAL + busy_timeout（waitress 16 线程下防 database is locked）
from sqlalchemy import event as sa_event


def _sqlite_pragmas(dbapi_conn, _):
    try:
        cur = dbapi_conn.cursor()
        cur.execute('PRAGMA journal_mode=WAL')
        cur.execute('PRAGMA busy_timeout=5000')
        cur.execute('PRAGMA synchronous=NORMAL')
        cur.close()
    except Exception:
        pass


# 事件监听在应用上下文内注册（Flask-SQLAlchemy 3.x 的 db.engine 需 current_app）
with app.app_context():
    sa_event.listen(db.engine, 'connect', _sqlite_pragmas)

# ── secret_key 持久化：重启后会话保持 ──
_secret_dir = trim_pkgvar if trim_pkgvar else os.path.join(BASE_DIR, 'instance')
try:
    os.makedirs(_secret_dir, exist_ok=True)
    try:
        os.chmod(_secret_dir, 0o700)
    except Exception:
        pass
    _secret_key = os.environ.get('SECRET_KEY', '')
    if not _secret_key:
        _secret_file = os.path.join(_secret_dir, 'secret_key')
        try:
            _secret_key = open(_secret_file).read().strip()
        except Exception:
            _secret_key = os.urandom(24).hex()
            try:
                with open(_secret_file, 'w') as f:
                    f.write(_secret_key)
                try:
                    os.chmod(_secret_file, 0o600)
                except Exception:
                    pass
            except Exception:
                pass
    app.secret_key = _secret_key
except Exception:
    app.secret_key = os.urandom(24).hex()

# ── 安全响应头（不要加 X-Frame-Options: DENY——fnOS 桌面 iframe 内嵌）──
@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    return response

# gzip 压缩（跳过文件下载：attachment 或已编码）
@app.after_request
def gzip_response(response):
    try:
        if response.headers.get('Content-Encoding'):
            return response
        if 'attachment' in (response.headers.get('Content-Disposition') or ''):
            return response  # 文件下载（含 xlsx 导出）不压缩，防程序化下载损坏
        cl = response.content_length or 0
        if cl > 1000 and cl < 50 * 1024 * 1024:
            accept = request.headers.get('Accept-Encoding', '')
            if 'gzip' in accept:
                ct = (response.headers.get('Content-Type', '') or '')
                if 'application/octet-stream' not in ct and 'image/' not in ct:
                    import gzip as gz
                    response.direct_passthrough = False
                    data = response.get_data()
                    if isinstance(data, str):
                        data = data.encode('utf-8')
                    response.set_data(gz.compress(data))
                    response.headers['Content-Encoding'] = 'gzip'
                    response.headers['Vary'] = 'Accept-Encoding'
    except Exception:
        pass
    return response

@app.template_filter('from_json')
def from_json_filter(s):
    try:
        return json.loads(s) if s else []
    except Exception:
        return []

def parse_json_list(s):
    """解析逗号分隔/JSON 的 ID 列表为 int 列表"""
    if not s:
        return []
    if isinstance(s, list):
        return [int(x) for x in s]
    try:
        v = json.loads(s)
        if isinstance(v, list):
            return [int(x) for x in v]
    except Exception:
        pass
    return [int(x) for x in re.split(r'[,，\s]+', str(s)) if str(x).strip().isdigit()]

app.jinja_env.globals['now'] = lambda: datetime.now()

# ── CSRF ──
def _get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = hashlib.sha256(os.urandom(32)).hexdigest()
        session['_csrf_token'] = token
    return token

app.jinja_env.globals['csrf_token'] = _get_csrf_token

@app.before_request
def csrf_protect():
    if request.method == 'POST' and request.endpoint not in ('static',):
        token = session.get('_csrf_token', '')
        sent = request.form.get('_csrf', '') or request.headers.get('X-CSRF-Token', '')
        if not token or not hmac.compare_digest(str(token), str(sent)):
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'ok': False, 'error': '页面已过期，请刷新后重试'}), 400
            flash('页面已过期，请刷新后重试')
            return redirect(request.referrer or url_for('index'))

# ── 登录失败限流 ──
_login_attempts = {}
_login_attempts_lock = threading.Lock()

def _login_throttled(ip):
    now = time.time()
    with _login_attempts_lock:
        rec = _login_attempts.get(ip)
        if rec and rec['count'] >= 5 and now - rec['first'] < 300:
            return True
    return False

def _login_fail(ip):
    now = time.time()
    with _login_attempts_lock:
        # 顺手清理超过 5 分钟的旧条目，防字典无限增长
        expired = [k for k, v in _login_attempts.items() if now - v['first'] > 300]
        for k in expired:
            _login_attempts.pop(k, None)
        rec = _login_attempts.get(ip)
        if not rec or now - rec['first'] > 300:
            _login_attempts[ip] = {'count': 1, 'first': now}
        else:
            rec['count'] += 1

def _login_ok(ip):
    with _login_attempts_lock:
        _login_attempts.pop(ip, None)

# ── 角色 ──
ROLE_ADMIN = 'admin'
ROLE_LEADER = 'leader'
ROLE_LABELS = {ROLE_ADMIN: '管理员', ROLE_LEADER: '领导'}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """仅管理员可操作（领导只读报表）"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录')
            return redirect(url_for('login'))
        u = db.session.get(User, session.get('user_id'))
        if not u or u.role != ROLE_ADMIN:
            flash('无权限操作（领导账号只读报表）')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

PUBLIC_ROUTES = {'login', 'logout', 'change_password', 'static'}

_LOG_MODULE_MAP = {
    'classes_add': '班级', 'classes_edit': '班级', 'classes_delete': '班级',
    'teachers_add': '教师', 'teachers_edit': '教师', 'teachers_delete': '教师',
    'courses_add': '课程', 'courses_edit': '课程', 'courses_delete': '课程',
    'classrooms_add': '教室', 'classrooms_edit': '教室', 'classrooms_delete': '教室',
    'textbooks_add': '教材', 'textbooks_edit': '教材', 'textbooks_delete': '教材',
    'textbook_stock': '教材',
    'orders_add': '征订', 'orders_status': '征订', 'orders_delete': '征订',
    'issues_add': '发书', 'issues_delete': '发书',
    'tasks_add': '教学任务', 'tasks_edit': '教学任务', 'tasks_delete': '教学任务',
    'schedule_cell_update': '课表', 'schedule_clear': '课表',
    'leaves_add': '调课', 'leaves_edit': '调课', 'leaves_delete': '调课', 'leaves_watch': '调课',
    'night_add': '夜自习', 'night_edit': '夜自习', 'night_delete': '夜自习',
    'overtimes_add': '加班', 'overtimes_delete': '加班',
    'fees_add': '管理费', 'fees_delete': '管理费',
    'semester_add': '学期', 'semester_delete': '学期', 'semester_set': '学期',
    'settings_save': '系统设置', 'import_do': '数据导入', 'night_import_do': '夜自习导入',
    'change_password': '账号',
}

BREADCRUMB_MAP = {
    'index': [('首页', '/')],
    'data_management': [('数据管理', '/data')],
    'data_import': [('数据管理', '/data')],
    'payments_page': [('补助发放', '/payments')],
    'payments_read': [('补助发放', '/payments')],
    'payments_save': [('补助发放', '/payments')],
    'payments_add': [('补助发放', '/payments')],
    'payments_export': [('补助发放', '/payments')],
    'classes_page': [('基础数据', ''), ('班级管理', '/classes')],
    'teachers_page': [('基础数据', ''), ('教师管理', '/teachers')],
    'courses_page': [('基础数据', ''), ('课程管理', '/courses')],
    'classrooms_page': [('基础数据', ''), ('教室管理', '/classrooms')],
    'textbooks_page': [('基础数据', ''), ('教材库', '/textbooks')],
    'import_page': [('基础数据', ''), ('数据导入', '/import')],
    'orders_page': [('订书发书', ''), ('征订计划', '/orders')],
    'issues_page': [('订书发书', ''), ('发书登记', '/issues')],
    'books_stats': [('订书发书', ''), ('统计导出', '/books/stats')],
    'tasks_page': [('排课管理', ''), ('教学任务', '/tasks')],
    'schedule_page': [('排课管理', ''), ('班级课表', '/schedule')],
    'schedule_teacher': [('排课管理', ''), ('教师课表', '/schedule/teacher')],
    'schedule_room': [('排课管理', ''), ('教室课表', '/schedule/room')],
    'leaves_page': [('调课请假', ''), ('请假看课', '/leaves')],
    'leaves_stats': [('调课请假', ''), ('看课统计', '/leaves/stats')],
    'standards_page': [('超课时', ''), ('课时标准', '/standards')],
    'holidays_page': [('超课时', ''), ('停课日', '/holidays')],
    'workload_page': [('超课时', ''), ('超课时统计', '/workload')],
    'night_page': [('夜自习', ''), ('排班管理', '/night')],
    'night_stats': [('夜自习', ''), ('统计补助', '/night/stats')],
    'overtimes_page': [('加班管理费', ''), ('加班登记', '/overtimes')],
    'fees_page': [('加班管理费', ''), ('管理费', '/fees')],
    'reports_page': [('领导报表', ''), ('综合报表', '/reports')],
    'settings_page': [('系统设置', ''), ('参数设置', '/settings')],
    'logs_page': [('系统设置', ''), ('操作日志', '/logs')],
    'semester_page': [('系统设置', ''), ('学期管理', '/semester')],
}


def paginate(q, per_page=50, page_arg='page'):
    """通用分页：返回 (rows, total, page, pages, qs)"""
    total = q.count()
    page = max(1, request.args.get(page_arg, 1, type=int))
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    rows = q.offset((page - 1) * per_page).limit(per_page).all()
    args = {k: v for k, v in request.args.items() if k != page_arg}
    qs = '&'.join('%s=%s' % (k, v) for k, v in args.items())
    return rows, total, page, pages, qs


app.jinja_env.globals['breadcrumb'] = lambda: BREADCRUMB_MAP.get(request.endpoint or '', [])

_IMPORT_ENDPOINTS = {'import_do', 'night_import_do'}


@app.after_request
def _log_operations(response):
    """记录写操作日志（POST 请求 + 登录/登出）；被权限拦截的请求不记"""
    try:
        if getattr(g, '_blocked', False):
            return response
        if request.method == 'POST' or request.endpoint in ('login', 'logout'):
            ep = request.endpoint or ''
            uid = session.get('user_id')
            uname = session.get('username', '')
            if ep == 'login':
                if response.status_code == 302:
                    db.session.add(OperationLog(user_id=uid, username=uname or request.form.get('username', ''),
                                                action='login', module='账号', detail='登录成功'))
            elif ep == 'logout':
                db.session.add(OperationLog(user_id=uid, username=uname, action='logout',
                                            module='账号', detail='退出登录'))
            elif ep in _LOG_MODULE_MAP:
                module = _LOG_MODULE_MAP[ep]
                if ep in _IMPORT_ENDPOINTS:
                    action = 'import'
                else:
                    action = 'delete' if ep.endswith('delete') else ('add' if ep.endswith('add') else 'edit')
                detail = request.form.get('name', request.form.get('username', ''))[:60]
                db.session.add(OperationLog(user_id=uid, username=uname, action=action,
                                            module=module, detail=detail))
            db.session.commit()
    except Exception:
        pass
    return response



@app.route('/search')
@login_required
def search_page():
    """全局搜索：教师/班级/课程/教材/教室"""
    q = request.args.get('q', '').strip()
    results = {'teachers': [], 'classes': [], 'courses': [], 'textbooks': [], 'rooms': []}
    if q:
        sid = get_current_semester_id()
        kw = '%' + q + '%'
        results['teachers'] = Teacher.query.filter_by(semester_id=sid) \
            .filter(Teacher.name.like(kw)).limit(10).all()
        results['classes'] = ClassInfo.query.filter_by(semester_id=sid) \
            .filter(ClassInfo.name.like(kw)).limit(10).all()
        results['courses'] = Course.query.filter_by(semester_id=sid) \
            .filter(Course.name.like(kw)).limit(10).all()
        results['textbooks'] = Textbook.query.filter_by(semester_id=sid) \
            .filter(Textbook.name.like(kw)).limit(10).all()
        results['rooms'] = Classroom.query.filter_by(semester_id=sid) \
            .filter(Classroom.name.like(kw)).limit(10).all()
    return render_template('search.html', q=q, results=results)


@app.route('/logs')
@admin_required
def logs_page():
    """操作日志"""
    q = OperationLog.query.order_by(OperationLog.id.desc())
    kw = request.args.get('q', '').strip()
    mod = request.args.get('module', '').strip()
    if kw:
        q = q.filter(OperationLog.detail.like('%' + kw + '%') |
                     OperationLog.username.like('%' + kw + '%'))
    if mod:
        q = q.filter(OperationLog.module == mod)
    total = q.count()
    per_page = 50
    page = max(1, request.args.get('page', 1, type=int))
    rows = q.offset((page - 1) * per_page).limit(per_page).all()
    modules = sorted({m for m, in db.session.query(OperationLog.module).distinct().all() if m})
    pages = (total + per_page - 1) // per_page
    return render_template('logs.html', rows=rows, total=total, page=page, pages=pages,
                           kw=kw, mod=mod, modules=modules)


@app.before_request
def check_login():
    if request.endpoint and request.endpoint not in PUBLIC_ROUTES and 'user_id' not in session:
        g._blocked = True
        flash('请先登录')
        return redirect(url_for('login'))
    # 领导账号：仅放行 首页/综合报表/报表导出，其余页面一律拦截（只读报表）
    # 注意排除 PUBLIC_ROUTES：leader 也必须能正常登录/退出/改密
    if request.endpoint and request.endpoint not in PUBLIC_ROUTES and 'user_id' in session:
        u = db.session.get(User, session.get('user_id'))
        if u and u.role != ROLE_ADMIN:
            if request.endpoint not in ('index', 'reports_page', 'reports_export'):
                g._blocked = True
                flash('无权限操作（领导账号只读综合报表）')
                return redirect(url_for('index'))
    return None

# ══════════════════════════════════════════════
# 数据模型
# ══════════════════════════════════════════════

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), default=ROLE_ADMIN)
    display_name = db.Column(db.String(64), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)

    def set_password(self, pwd):
        # CLT Python 无 scrypt，统一用 pbkdf2:sha256
        self.password_hash = generate_password_hash(pwd, method='pbkdf2:sha256')

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)

class Semester(db.Model):
    __tablename__ = 'semester'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    teaching_weeks = db.Column(db.Float, nullable=True)  # 手动覆盖有效教学周数，空=自动计算
    created_at = db.Column(db.DateTime, default=datetime.now)

    def effective_weeks(self):
        """有效教学周数：手动值优先（整数），否则按自然周计算——放假停课也按一整周算，恒为整数。
        第 1 周 = 包含学期开始日的那一周（以该周周日为基准），与周次/周期基准一致"""
        if self.teaching_weeks:
            return int(round(float(self.teaching_weeks)))
        base = self.start_date - timedelta(days=(self.start_date.weekday() + 1) % 7)
        return int(((self.end_date - base).days // 7) + 1)

class ClassInfo(db.Model):
    __tablename__ = 'class_info'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    grade = db.Column(db.String(32), default='')
    head_teacher = db.Column(db.String(32), default='')
    student_count = db.Column(db.Integer, default=0)
    classroom_id = db.Column(db.Integer, default=None)  # 本班固定教室
    remark = db.Column(db.String(255), default='')

class Teacher(db.Model):
    __tablename__ = 'teacher'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    position = db.Column(db.String(32), default='专任教师')   # 职务：专任教师/教研室主任/中层干部/行政兼课...
    subject_category = db.Column(db.String(32), default='专业课')  # 学科类别：文化课/专业课/实训课...
    phone = db.Column(db.String(32), default='')
    is_active = db.Column(db.Boolean, default=True)
    remark = db.Column(db.String(255), default='')

class Course(db.Model):
    __tablename__ = 'course'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    category = db.Column(db.String(32), default='专业课')  # 文化课/专业课/实训课/公共课/体育
    default_weekly_hours = db.Column(db.Integer, default=4)
    remark = db.Column(db.String(255), default='')

class Classroom(db.Model):
    __tablename__ = 'classroom'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)   # 显示名 = 楼名+门牌号（自动拼接）
    building = db.Column(db.String(64), default='')   # 楼名，如：实训楼
    room_no = db.Column(db.String(32), default='')    # 门牌号，如：201
    ctype = db.Column(db.String(32), default='普通教室')  # 普通教室/实训室/机房/体育场地
    capacity = db.Column(db.Integer, default=50)
    remark = db.Column(db.String(255), default='')

class Textbook(db.Model):
    __tablename__ = 'textbook'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    isbn = db.Column(db.String(32), default='')
    publisher = db.Column(db.String(128), default='')
    author = db.Column(db.String(64), default='')
    price = db.Column(db.Float, default=0)
    version = db.Column(db.String(32), default='')       # 版次
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=True)  # 适用课程
    stock = db.Column(db.Integer, default=0)             # 当前库存
    remark = db.Column(db.String(255), default='')

class OrderPlan(db.Model):
    """征订计划"""
    __tablename__ = 'order_plan'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=True)
    textbook_id = db.Column(db.Integer, db.ForeignKey('textbook.id'), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class_info.id'), nullable=True)  # 空=全校/按课程
    major = db.Column(db.String(32), default='')      # 专业（如 供电/机电/汽修）
    semester_no = db.Column(db.Integer, default=1)    # 学期序数（1-6）
    quantity = db.Column(db.Integer, default=0)
    unit_price = db.Column(db.Float, default=0)          # 成交单价（默认取教材库价格）
    status = db.Column(db.String(16), default='draft')   # draft/approved/arrived
    remark = db.Column(db.String(255), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)

class BookIssue(db.Model):
    """发书记录：班级发书 / 教师教本"""
    __tablename__ = 'book_issue'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    issue_type = db.Column(db.String(16), default='class')  # class/teacher
    class_id = db.Column(db.Integer, db.ForeignKey('class_info.id'), nullable=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True)
    textbook_id = db.Column(db.Integer, db.ForeignKey('textbook.id'), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    signer = db.Column(db.String(64), default='')        # 领取人/签收
    issue_date = db.Column(db.Date, default=date.today)
    remark = db.Column(db.String(255), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)

class TeachingTask(db.Model):
    """教学任务：班级(可合班)-课程-教师-周课时-教室"""
    __tablename__ = 'teaching_task'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    class_ids = db.Column(db.String(255), default='')    # JSON/逗号分隔，支持合班
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    weekly_hours = db.Column(db.Integer, default=2)      # 每周节数
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=True)  # 指定教室（可空=自动分配）
    week_type = db.Column(db.String(8), default='every') # every/odd(单周)/even(双周)
    remark = db.Column(db.String(255), default='')

    def classes(self):
        return parse_json_list(self.class_ids)

class ScheduleCell(db.Model):
    """课表单元"""
    __tablename__ = 'schedule_cell'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('teaching_task.id'), nullable=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class_info.id'), nullable=False)
    weekday = db.Column(db.Integer, nullable=False)      # 1=周一 ...
    period = db.Column(db.Integer, nullable=False)       # 第几节
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=True)
    week_type = db.Column(db.String(8), default='every') # every/odd/even

class Holiday(db.Model):
    """节假日/停课日（超课时统计扣减）"""
    __tablename__ = 'holiday'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    holiday_date = db.Column(db.Date, nullable=False)
    name = db.Column(db.String(64), default='放假')
    remark = db.Column(db.String(255), default='')

class LeaveRequest(db.Model):
    """教师请假 → 审批 → 安排看课教师（补助）"""
    __tablename__ = 'leave_request'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    leave_date = db.Column(db.Date, nullable=False)
    periods = db.Column(db.String(32), default='')       # JSON 节次列表 [2,3]
    reason = db.Column(db.String(255), default='')
    leave_type = db.Column(db.String(8), default='调课')   # 换课（顶课教师上课）/ 调课（顶课教师只看班）
    status = db.Column(db.String(16), default='pending') # pending/approved/rejected
    approver = db.Column(db.String(64), default='')
    approved_at = db.Column(db.DateTime, nullable=True)
    watch_teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True)  # 看课教师
    watch_amount = db.Column(db.Float, default=0)        # 看课补助金额
    watch_note = db.Column(db.String(255), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)

    def period_list(self):
        return parse_json_list(self.periods)

class BookStockLog(db.Model):
    """教材出入库流水"""
    __tablename__ = 'book_stock_log'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    textbook_id = db.Column(db.Integer, db.ForeignKey('textbook.id'), nullable=False)
    change_type = db.Column(db.String(8), default='in')   # in=入库 out=出库
    qty = db.Column(db.Integer, default=0)
    note = db.Column(db.String(255), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)

class Payment(db.Model):
    """补助发放：每 4 周周期，按 项目×教师 记录金额（自动读取 + 可手动修改）"""
    __tablename__ = 'payment'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False, index=True)
    period_no = db.Column(db.Integer, default=1, index=True)     # 第 N 个 4 周周期
    teacher_id = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(16), nullable=False)           # 调课/超课时/管理/夜自习/出卷/监考
    amount = db.Column(db.Float, default=0)
    source = db.Column(db.String(8), default='auto')             # auto=从其他项目读取 manual=手动
    note = db.Column(db.String(64), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)


class OperationLog(db.Model):
    """操作日志（谁在何时做了什么）"""
    __tablename__ = 'operation_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(64), default='')
    action = db.Column(db.String(16), default='')   # login/logout/add/edit/delete/import/export
    module = db.Column(db.String(32), default='')
    detail = db.Column(db.String(500), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)

class NightShift(db.Model):
    """夜自习排班"""
    __tablename__ = 'night_shift'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    shift_date = db.Column(db.Date, nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class_info.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    status = db.Column(db.String(16), default='scheduled')  # scheduled/confirmed/absent
    note = db.Column(db.String(255), default='')

class Overtime(db.Model):
    """加班记录"""
    __tablename__ = 'overtime'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    work_date = db.Column(db.Date, nullable=False)
    time_range = db.Column(db.String(64), default='')    # 如 8:00-12:00
    category = db.Column(db.String(32), default='周末')   # 周末/节假日/临时/其他
    reason = db.Column(db.String(255), default='')
    hours = db.Column(db.Float, default=0)
    amount = db.Column(db.Float, default=0)
    status = db.Column(db.String(16), default='confirmed')  # draft/confirmed
    created_at = db.Column(db.DateTime, default=datetime.now)

class ManagementFee(db.Model):
    """管理费（班主任/教研组长/专业部长等职务津贴）"""
    __tablename__ = 'management_fee'
    id = db.Column(db.Integer, primary_key=True)
    semester_id = db.Column(db.Integer, db.ForeignKey('semester.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    fee_type = db.Column(db.String(32), default='班主任费')
    month = db.Column(db.String(7), default='')          # YYYY-MM
    amount = db.Column(db.Float, default=0)
    note = db.Column(db.String(255), default='')

class PositionStandard(db.Model):
    """职务标准课时（超课时用）"""
    __tablename__ = 'position_standard'
    id = db.Column(db.Integer, primary_key=True)
    position = db.Column(db.String(32), unique=True, nullable=False)
    weekly_std_hours = db.Column(db.Float, default=12)
    note = db.Column(db.String(255), default='')

class CourseCoefficient(db.Model):
    """学科类别课时系数"""
    __tablename__ = 'course_coefficient'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(32), unique=True, nullable=False)
    coefficient = db.Column(db.Float, default=1.0)
    note = db.Column(db.String(255), default='')

class Setting(db.Model):
    __tablename__ = 'setting'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(255), default='')
    remark = db.Column(db.String(255), default='')

# ══════════════════════════════════════════════
# 辅助函数
# ══════════════════════════════════════════════

def get_setting(key, default=''):
    s = Setting.query.filter_by(key=key).first()
    return s.value if s and s.value not in (None, '') else default

def get_setting_int(key, default=0):
    try:
        return int(float(get_setting(key, default)))
    except Exception:
        return default

def get_setting_float(key, default=0.0):
    try:
        return float(get_setting(key, default))
    except Exception:
        return default

def get_current_semester_id():
    """当前学期：session 优先，否则取开始日期最近的学期"""
    sid = session.get('semester_id')
    if sid:
        s = db.session.get(Semester, sid) if sid else None
        if s:
            return s.id
    s = Semester.query.order_by(Semester.start_date.desc()).first()
    if s:
        session['semester_id'] = s.id
        return s.id
    return None

def get_semester():
    sid = get_current_semester_id()
    return db.session.get(Semester, sid) if sid else None

def sem_filter(query):
    """学期过滤"""
    sid = get_current_semester_id()
    return query.filter_by(semester_id=sid) if sid else query

def period_list():
    """每天节次列表，如 [1..8]"""
    return list(range(1, get_setting_int('periods_per_day', 8) + 1))

def weekday_list():
    workdays = get_setting_int('workdays', 5)
    return list(range(1, workdays + 1))

def weekday_label(wd):
    return ['周一', '周二', '周三', '周四', '周五', '周六', '周日'][wd - 1] if 1 <= wd <= 7 else str(wd)

def week_type_conflict(wt1, wt2):
    """判断两个课表单元是否在周类型上冲突（占同一周）"""
    if wt1 == wt2:
        return True
    if wt1 == 'every' or wt2 == 'every':
        return True
    return False  # odd vs even 不冲突

def class_name(cid):
    c = db.session.get(ClassInfo, cid) if cid else None
    return c.name if c else ''

def room_name(rid):
    r = db.session.get(Classroom, rid) if rid else None
    return r.name if r else ''

def class_room_id(cid):
    c = db.session.get(ClassInfo, cid) if cid else None
    return c.classroom_id if c else None

def _ref_count(kind, oid):
    """统计某基础数据对象被多少条业务记录引用（删除前拦截用，防孤儿数据）"""
    sid = get_current_semester_id()
    n = 0
    if kind == 'teacher':
        n += TeachingTask.query.filter_by(semester_id=sid, teacher_id=oid).count()
        n += ScheduleCell.query.filter_by(semester_id=sid, teacher_id=oid).count()
        n += LeaveRequest.query.filter_by(semester_id=sid, teacher_id=oid).count()
        n += NightShift.query.filter_by(semester_id=sid, teacher_id=oid).count()
        n += Overtime.query.filter_by(semester_id=sid, teacher_id=oid).count()
        n += ManagementFee.query.filter_by(semester_id=sid, teacher_id=oid).count()
        n += BookIssue.query.filter_by(semester_id=sid, teacher_id=oid).count()
    elif kind == 'class':
        n += ScheduleCell.query.filter_by(semester_id=sid, class_id=oid).count()
        n += OrderPlan.query.filter_by(semester_id=sid, class_id=oid).count()
        n += BookIssue.query.filter_by(semester_id=sid, class_id=oid).count()
        n += NightShift.query.filter_by(semester_id=sid, class_id=oid).count()
        for t in TeachingTask.query.filter_by(semester_id=sid).all():
            if oid in t.classes():
                n += 1
    elif kind == 'course':
        n += TeachingTask.query.filter_by(semester_id=sid, course_id=oid).count()
        n += ScheduleCell.query.filter_by(semester_id=sid, course_id=oid).count()
        n += Textbook.query.filter_by(semester_id=sid, course_id=oid).count()
        n += OrderPlan.query.filter_by(semester_id=sid, course_id=oid).count()
    elif kind == 'room':
        n += TeachingTask.query.filter_by(semester_id=sid, classroom_id=oid).count()
        n += ScheduleCell.query.filter_by(semester_id=sid, classroom_id=oid).count()
    elif kind == 'textbook':
        n += OrderPlan.query.filter_by(semester_id=sid, textbook_id=oid).count()
        n += BookIssue.query.filter_by(semester_id=sid, textbook_id=oid).count()
    return n

def teacher_name(tid):
    t = db.session.get(Teacher, tid) if tid else None
    return t.name if t else ''

def course_name(cid):
    c = db.session.get(Course, cid) if cid else None
    return c.name if c else ''

def classroom_name(cid):
    c = db.session.get(Classroom, cid) if cid else None
    return c.name if c else ''

def task_classes_display(task):
    ids = task.classes()
    names = [class_name(i) for i in ids]
    return '+'.join(names) if names else ''

# 注册业务辅助函数到模板全局（模板里直接调用）
app.jinja_env.globals.update({
    'course_name': course_name, 'teacher_name': teacher_name,
    'class_name': class_name, 'classroom_name': classroom_name,
    'room_name': room_name, 'class_room_id': class_room_id,
    'weekday_label': weekday_label, 'parse_json_list': parse_json_list,
})

@app.context_processor
def inject_semester():
    if request.endpoint in PUBLIC_ROUTES:
        return dict(semesters=[], current_semester=None)
    semesters = Semester.query.order_by(Semester.start_date.desc()).all()
    current = get_semester()
    user = None
    if session.get('user_id'):
        user = db.session.get(User, session.get('user_id'))
    return dict(semesters=semesters, current_semester=current,
                current_user=user, role_labels=ROLE_LABELS)

# ══════════════════════════════════════════════
# 认证路由
# ══════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if _login_throttled(ip):
            flash('尝试次数过多，请5分钟后再试')
            return render_template('login.html')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        u = User.query.filter_by(username=username).first()
        if not u or not u.check_password(password):
            _login_fail(ip)
            flash('用户名或密码错误')
            return render_template('login.html')
        _login_ok(ip)
        session.clear()
        session['user_id'] = u.id
        session['username'] = u.username
        session['_csrf_token'] = _get_csrf_token()
        sid = get_current_semester_id()
        if sid:
            session['semester_id'] = sid
        flash(f'欢迎回来，{u.display_name or u.username}')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('已退出登录')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if _login_throttled(ip):
            flash('尝试次数过多，请5分钟后再试')
            return redirect(url_for('login'))
        if session.get('user_id'):
            u = db.session.get(User, session['user_id'])
            if not u:
                session.clear()
                return redirect(url_for('login'))
            old = request.form.get('old_password', '')
            if not u.check_password(old):
                _login_fail(ip)
                flash('当前密码错误')
                return render_template('change_password.html', logged_in=True, username=u.username)
        else:
            # 未登录：验证 用户名+当前密码
            username = request.form.get('username', '').strip()
            old = request.form.get('old_password', '')
            u = User.query.filter_by(username=username).first()
            if not u or not u.check_password(old):
                _login_fail(ip)
                flash('用户名或当前密码错误')
                return render_template('change_password.html', logged_in=False, username='')
        new1 = request.form.get('new_password', '')
        new2 = request.form.get('new_password2', '') or request.form.get('confirm_password', '')
        if len(new1) < 8:
            flash('新密码至少8位')
            return render_template('change_password.html', logged_in=bool(session.get('user_id')), username=u.username)
        if new1 != new2:
            flash('两次输入的新密码不一致')
            return render_template('change_password.html', logged_in=bool(session.get('user_id')), username=u.username)
        u.set_password(new1)
        db.session.commit()
        _login_ok(ip)
        # 先清会话再 flash（flash 存 session，顺序反了消息会丢）
        session.clear()
        flash('密码修改成功，请重新登录')
        return redirect(url_for('login'))
    username = ''
    if session.get('user_id'):
        u = db.session.get(User, session.get('user_id'))
        username = u.username if u else ''
    return render_template('change_password.html', logged_in=bool(session.get('user_id')), username=username)

# ══════════════════════════════════════════════
# 首页仪表盘
# ══════════════════════════════════════════════

BACKUP_DIR = os.path.join(BASE_DIR, 'instance', 'backups')
os.makedirs(BACKUP_DIR, exist_ok=True)


def _db_path():
    """当前 SQLite 数据库文件路径（URI 相对路径 = Flask-SQLAlchemy 的 instance 目录）"""
    uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if uri.startswith('sqlite:///'):
        rel = uri[len('sqlite:///'):]
        if rel.startswith('/'):
            return rel  # 绝对路径
        return os.path.join(BASE_DIR, 'instance', rel)
    return os.path.join(BASE_DIR, 'instance', 'edu_admin.db')


def _create_backup(note=''):
    """在线安全备份当前数据库（sqlite3 backup API，服务运行中一致）"""
    db_path = _db_path()
    if not os.path.exists(db_path):
        return None
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    name = 'edu_backup_%s_%s%s.db' % (ts, os.urandom(2).hex(), '_' + note if note else '')
    dst = os.path.join(BACKUP_DIR, name)
    import sqlite3
    src_conn = sqlite3.connect(db_path)
    try:
        dst_conn = sqlite3.connect(dst)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    return name


def _friendly_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return '%.1f %s' % (size, unit)
        size /= 1024
    return '%.1f GB' % size


def _db_size():
    """数据库总大小（含 WAL/SHM 附属文件）"""
    db_path = _db_path()
    total = 0
    for p in (db_path, db_path + '-wal', db_path + '-shm'):
        try:
            total += os.path.getsize(p)
        except Exception:
            pass
    return _friendly_size(total) if total else '0 B'


@app.route('/data')
@login_required
def data_management():
    """数据管理：统计 + 备份 + 导出 + 恢复 + 重置"""
    sid = get_current_semester_id()
    stats = {
        'db_size': _db_size(),
        'classes': ClassInfo.query.filter_by(semester_id=sid).count(),
        'teachers': Teacher.query.filter_by(semester_id=sid).count(),
        'courses': Course.query.filter_by(semester_id=sid).count(),
        'rooms': Classroom.query.filter_by(semester_id=sid).count(),
        'textbooks': Textbook.query.filter_by(semester_id=sid).count(),
        'tasks': TeachingTask.query.filter_by(semester_id=sid).count(),
        'cells': ScheduleCell.query.filter_by(semester_id=sid).count(),
        'orders': OrderPlan.query.filter_by(semester_id=sid).count(),
        'issues': BookIssue.query.filter_by(semester_id=sid).count(),
        'leaves': LeaveRequest.query.filter_by(semester_id=sid).count(),
        'night': NightShift.query.filter_by(semester_id=sid).count(),
        'overtimes': Overtime.query.filter_by(semester_id=sid).count(),
        'fees': ManagementFee.query.filter_by(semester_id=sid).count(),
        'logs': OperationLog.query.count(),
    }
    backups = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not fname.endswith('.db'):
            continue
        fpath = os.path.join(BACKUP_DIR, fname)
        mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
        backups.append({'name': fname, 'size': _friendly_size(os.path.getsize(fpath)),
                        'mtime': mtime.strftime('%Y-%m-%d %H:%M:%S')})
    return render_template('data.html', stats=stats, backups=backups)


@app.route('/data/backup', methods=['POST'])
@admin_required
def data_backup():
    """创建备份"""
    name = _create_backup()
    if not name:
        flash('数据库文件不存在，无法备份')
        return redirect(url_for('data_management'))
    flash('备份已创建：%s' % name)
    return redirect(url_for('data_management'))


@app.route('/data/export')
@login_required
def data_export():
    """全量导出：下载当前数据库（先做一致性备份再发送）"""
    db_path = _db_path()
    if not os.path.exists(db_path):
        flash('数据库文件不存在')
        return redirect(url_for('data_management'))
    tmp = _create_backup('export')
    if not tmp:
        flash('导出失败')
        return redirect(url_for('data_management'))
    tmp_path = os.path.join(BACKUP_DIR, tmp)
    try:
        return send_file(tmp_path, mimetype='application/octet-stream', as_attachment=True,
                         download_name='edu_admin_%s.db' % datetime.now().strftime('%Y%m%d_%H%M%S'))
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


@app.route('/data/upload', methods=['POST'])
@admin_required
def data_upload():
    """上传 .db 备份文件恢复数据"""
    f = request.files.get('file')
    if not f or not f.filename:
        flash('请选择备份文件')
        return redirect(url_for('data_management'))
    if not f.filename.lower().endswith('.db'):
        flash('仅支持 .db 备份文件')
        return redirect(url_for('data_management'))
    db_path = _db_path()
    _create_backup('restore_auto')  # 恢复前自动备份当前数据
    db.session.remove()
    db.engine.dispose()
    for suffix in ('-wal', '-shm'):
        p = db_path + suffix
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    f.save(db_path)
    db.create_all()
    flash('数据已从「%s」恢复（恢复前已自动备份）' % f.filename)
    return redirect(url_for('data_management'))


@app.route('/data/backups/<filename>/download')
@admin_required
def data_backup_download(filename):
    safe = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, safe)
    if not os.path.exists(fpath):
        flash('备份文件不存在')
        return redirect(url_for('data_management'))
    return send_file(fpath, mimetype='application/octet-stream', as_attachment=True, download_name=safe)


@app.route('/data/backups/<filename>/delete', methods=['POST'])
@admin_required
def data_backup_delete(filename):
    safe = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, safe)
    if os.path.exists(fpath):
        os.remove(fpath)
        flash('备份已删除')
    else:
        flash('备份文件不存在')
    return redirect(url_for('data_management'))


@app.route('/data/restore/<filename>', methods=['POST'])
@admin_required
def data_restore_from_backup(filename):
    """从服务器上的备份恢复（恢复前自动备份当前数据）"""
    safe = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, safe)
    if not os.path.exists(fpath):
        flash('备份文件不存在')
        return redirect(url_for('data_management'))
    db_path = _db_path()
    _create_backup('restore_auto')
    db.session.remove()
    db.engine.dispose()
    for suffix in ('-wal', '-shm'):
        p = db_path + suffix
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    import shutil
    shutil.copy2(fpath, db_path)
    db.create_all()
    flash('数据已从「%s」恢复' % safe)
    return redirect(url_for('data_management'))


@app.route('/data/reset', methods=['POST'])
@admin_required
def data_reset():
    """【危险】清空全部业务数据（保留管理员账号），需输入确认文字"""
    confirm = request.form.get('confirm', '').strip()
    if confirm != '清空':
        flash('确认文字不正确（需输入"清空"）')
        return redirect(url_for('data_management'))
    db_path = _db_path()
    _create_backup('reset_auto')  # 重置前自动备份
    models = [ClassInfo, Teacher, Course, Classroom, Textbook, OrderPlan, BookIssue,
              TeachingTask, ScheduleCell, LeaveRequest, NightShift, Overtime,
              ManagementFee, OperationLog, BookStockLog, Holiday, Semester, Payment]
    # 课时标准/学科系数属系统配置（与系统设置同），重置不删除
    for m in models:
        try:
            m.query.delete()
        except Exception:
            pass
    db.session.commit()
    flash('全部业务数据已清空（管理员账号保留；重置前已自动备份）')
    return redirect(url_for('data_management'))


PAYMENT_CATEGORIES = ['调课', '超课时', '管理', '夜自习', '出卷', '监考']


def _period_range(sid, pno):
    sem = db.session.get(Semester, sid) if sid else None
    periods = _period_weeks(sem) if sem else []
    return next((p for p in periods if p[0] == pno), None)


def _payment_source(sid, pno):
    """从各项目读取第 pno 周期补助：{category: {teacher_id: amount}}"""
    data = {c: {} for c in PAYMENT_CATEGORIES}
    sem = db.session.get(Semester, sid) if sid else None
    pr = _period_range(sid, pno)
    if not sem or not pr:
        return data
    p_start, p_end = pr[1], pr[2]
    unit_night = get_setting_float('night_shift_unit_price', 0)
    # 调课（顶课补助）：已生效且有顶课教师，日期在周期内
    lvs = LeaveRequest.query.filter_by(semester_id=sid, status='approved') \
        .filter(LeaveRequest.watch_teacher_id.isnot(None)) \
        .filter(LeaveRequest.leave_date >= p_start, LeaveRequest.leave_date <= p_end).all()
    for lv in lvs:
        data['调课'][lv.watch_teacher_id] = data['调课'].get(lv.watch_teacher_id, 0) + (lv.watch_amount or 0)
    # 超课时：周期统计金额
    rows, _ = workload_period_rows(sid, pno)
    for r in rows:
        if r['amount'] > 0:
            data['超课时'][r['teacher'].id] = r['amount']
    # 管理费：按月份归属周期（含该月 1 日的周期），避免跨月周期双计
    sem_sun = sem.start_date - timedelta(days=(sem.start_date.weekday() + 1) % 7)
    month_period = {}
    d = sem.start_date
    while d <= sem.end_date:
        m = d.strftime('%Y-%m')
        if m not in month_period:
            first = d.replace(day=1)
            wno = ((first - sem_sun).days // 7) + 1
            month_period[m] = max(1, (wno - 1) // 4 + 1)
        d += timedelta(days=1)
    fees = ManagementFee.query.filter_by(semester_id=sid).all()
    for f in fees:
        if month_period.get(f.month) == pno:
            data['管理'][f.teacher_id] = data['管理'].get(f.teacher_id, 0) + (f.amount or 0)
    # 加班费也归入「管理」
    ots = Overtime.query.filter_by(semester_id=sid) \
        .filter(Overtime.work_date >= p_start, Overtime.work_date <= p_end).all()
    for o in ots:
        data['管理'][o.teacher_id] = data['管理'].get(o.teacher_id, 0) + (o.amount or 0)
    # 夜自习：周期内有效记录 × 单价
    shifts = NightShift.query.filter_by(semester_id=sid) \
        .filter(NightShift.status != 'absent') \
        .filter(NightShift.shift_date >= p_start, NightShift.shift_date <= p_end).all()
    for s in shifts:
        data['夜自习'][s.teacher_id] = data['夜自习'].get(s.teacher_id, 0) + unit_night
    return data


@app.route('/payments')
@login_required
def payments_page():
    sid = get_current_semester_id()
    sem = db.session.get(Semester, sid) if sid else None
    period_nos = [p[0] for p in _period_weeks(sem)] if sem else []
    p_str = request.args.get('period', '')
    if p_str.isdigit() and int(p_str) in period_nos:
        cur = int(p_str)
    else:
        cur = _current_period_no(sid)
        if cur not in period_nos:
            cur = period_nos[-1] if period_nos else 1
    recs = Payment.query.filter_by(semester_id=sid, period_no=cur).all()
    grid = {}
    for r in recs:
        grid[(r.category, r.teacher_id)] = r
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    source_data = _payment_source(sid, cur)
    pr = _period_range(sid, cur)
    period_range_str = '%s ~ %s' % (pr[1].strftime('%m-%d'), pr[2].strftime('%m-%d')) if pr else ''
    return render_template('payments.html', period_nos=period_nos, cur=cur, grid=grid,
                           teachers=teachers, source_data=source_data,
                           period_range_str=period_range_str, categories=PAYMENT_CATEGORIES)


@app.route('/payments/read', methods=['POST'])
@admin_required
def payments_read():
    """从其他项目读取当前周期补助（可指定项目，空=全部）"""
    sid = get_current_semester_id()
    pno = request.form.get('period', '1')
    pno = int(pno) if pno.isdigit() else 1
    cat = request.form.get('category', '').strip()
    cats = [cat] if cat in PAYMENT_CATEGORIES else PAYMENT_CATEGORIES
    data = _payment_source(sid, pno)
    total = 0
    for c in cats:
        for tid, amt in data[c].items():
            rec = Payment.query.filter_by(semester_id=sid, period_no=pno, teacher_id=tid, category=c).first()
            if rec:
                rec.amount = round(amt, 2)
                rec.source = 'auto'
                rec.note = ''
            else:
                db.session.add(Payment(semester_id=sid, period_no=pno, teacher_id=tid,
                                       category=c, amount=round(amt, 2), source='auto'))
            total += 1
    db.session.commit()
    flash('已从其他项目读取：%s %d 条（第 %d 周期）' % ('、'.join(cats), total, pno))
    return redirect(url_for('payments_page', period=pno))


@app.route('/payments/save', methods=['POST'])
@admin_required
def payments_save():
    """批量保存当前周期发放金额（amount<=0 视为删除该行）"""
    sid = get_current_semester_id()
    pno = request.form.get('period', '1')
    pno = int(pno) if pno.isdigit() else 1
    saved = 0
    for key, val in request.form.items():
        if not key.startswith('amt_'):
            continue
        try:
            cat, tid = key[len('amt_'):].rsplit('_', 1)
            amount = float(val or 0)
            tid = int(tid)
        except Exception:
            continue
        if cat not in PAYMENT_CATEGORIES:
            continue
        rec = Payment.query.filter_by(semester_id=sid, period_no=pno, teacher_id=tid, category=cat).first()
        if amount <= 0:
            if rec:
                db.session.delete(rec)
                saved += 1
            continue
        if rec:
            # 金额与自动读取值不一致 → 标记为手动调整
            if rec.source == 'auto' and abs((rec.amount or 0) - amount) > 0.005:
                rec.source = 'manual'
            rec.amount = round(amount, 2)
        else:
            db.session.add(Payment(semester_id=sid, period_no=pno, teacher_id=tid,
                                   category=cat, amount=round(amount, 2), source='manual'))
        saved += 1
    db.session.commit()
    flash('补助发放已保存（%d 行，第 %d 周期）' % (saved, pno))
    return redirect(url_for('payments_page', period=pno))


@app.route('/payments/add', methods=['POST'])
@admin_required
def payments_add():
    """手动添加一笔补助（出卷/监考等无数据源项目）"""
    sid = get_current_semester_id()
    pno = request.form.get('period', '1')
    pno = int(pno) if pno.isdigit() else 1
    cat = request.form.get('category', '').strip()
    tid = request.form.get('teacher_id', '').strip()
    amount = request.form.get('amount', '').strip()
    if cat not in PAYMENT_CATEGORIES or not tid.isdigit():
        flash('请选择项目与教师')
        return redirect(url_for('payments_page', period=pno))
    try:
        amount = float(amount or 0)
    except Exception:
        amount = 0
    if amount <= 0:
        flash('金额必须大于 0')
        return redirect(url_for('payments_page', period=pno))
    rec = Payment.query.filter_by(semester_id=sid, period_no=pno, teacher_id=int(tid), category=cat).first()
    if rec:
        rec.amount = round(rec.amount + amount, 2)
        rec.source = 'manual'
    else:
        db.session.add(Payment(semester_id=sid, period_no=pno, teacher_id=int(tid),
                               category=cat, amount=round(amount, 2), source='manual'))
    db.session.commit()
    flash('已添加：%s × %s（%s 元）' % (cat, teacher_name(int(tid)), round(amount, 2)))
    return redirect(url_for('payments_page', period=pno))


@app.route('/payments/<int:pid>/delete', methods=['POST'])
@admin_required
def payments_delete(pid):
    rec = db.session.get(Payment, pid)
    if rec:
        pno = rec.period_no
        db.session.delete(rec)
        db.session.commit()
        flash('已删除该笔补助')
        return redirect(url_for('payments_page', period=pno))
    flash('记录不存在')
    return redirect(url_for('payments_page'))


@app.route('/payments/export')
@login_required
def payments_export():
    """导出补助发放表：夜自习按教务处模板（一年级/二年级 两张表）+ 其他项目一张表"""
    sid = get_current_semester_id()
    pno = request.args.get('period', '1')
    pno = int(pno) if pno.isdigit() else 1
    sem = db.session.get(Semester, sid) if sid else None
    recs = Payment.query.filter_by(semester_id=sid, period_no=pno).all()
    by_cat = {}
    for r in recs:
        by_cat.setdefault(r.category, {})[r.teacher_id] = r.amount
    # 夜自习：按固定名单统计（次数 = 金额 ÷ 单价）
    unit = get_setting_float('night_shift_unit_price', 0)
    counts_y1 = {}
    counts_y2 = {}
    for tid, amt in by_cat.get('夜自习', {}).items():
        name = teacher_name(tid)
        cnt = round(amt / unit) if unit else 0
        if name in NIGHT_YEAR1_TEACHERS:
            counts_y1[name] = cnt
        elif name in NIGHT_YEAR2_TEACHERS:
            counts_y2[name] = cnt
    # 只显示本期有数据的项目；本期无数据的项目不出现在导出中
    others = [c for c in PAYMENT_CATEGORIES if c != '夜自习']
    # 名单外教师的夜自习金额（固定名单匹配不到的，如临时代课教师）
    night_extra = {}
    for tid, amt in by_cat.get('夜自习', {}).items():
        if teacher_name(tid) not in NIGHT_YEAR1_TEACHERS and teacher_name(tid) not in NIGHT_YEAR2_TEACHERS:
            night_extra[tid] = amt
    if night_extra:
        others = others + ['夜自习（名单外）']
    others_active = [c for c in others if (by_cat.get(c) if c != '夜自习（名单外）' else night_extra)]
    has_night = bool(counts_y1) or bool(counts_y2)
    if not has_night and not others_active:
        flash('本期暂无任何补助数据，无需导出')
        return redirect(url_for('payments_page', period=pno))
    from openpyxl import Workbook
    if has_night:
        wb = _night_stat_workbook(pno, counts_y1, counts_y2, sem, unit)
    else:
        wb = Workbook()
        wb.remove(wb.active)
    # 其他项目 sheet（只显示有数据的项目列）
    if others_active:
        from openpyxl.styles import Font, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
        tids = sorted({tid for c in others_active for tid in (by_cat.get(c, {}) if c != '夜自习（名单外）' else night_extra)})
        ws = wb.create_sheet('其他项目')
        ws.append(['教师'] + others_active + ['合计'])
        for c in ws[1]:
            c.font = Font(name='宋体', size=12, bold=True)
            c.alignment = Alignment(horizontal='center')
            c.border = Border(left=Side(style='thin'), right=Side(style='thin'),
                              top=Side(style='thin'), bottom=Side(style='thin'))
        for tid in tids:
            row = [teacher_name(tid)]
            total = 0.0
            for c in others_active:
                amt = round((by_cat.get(c, {}).get(tid, 0) if c != '夜自习（名单外）' else night_extra.get(tid, 0)), 2)
                row.append(amt)
                total += amt
            row.append(round(total, 2))
            ws.append(row)
        ws.column_dimensions['A'].width = 12
        for i in range(2, len(others_active) + 3):
            ws.column_dimensions[get_column_letter(i)].width = 10
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name='补助发放_第%d周期.xlsx' % pno,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# ── 夜自习津贴发放表（严格按教务处模板格式，教师名单固定）──
NIGHT_YEAR1_TEACHERS = ['曾鸿运', '郑化军', '陈惠仁', '张生武', '王登学', '邴喜红', '齐江', '邱俊科',
                        '魏孔江', '陆泽龙', '白刚', '费俊娥', '金柏彤', '蔡娟娟', '张宝龙', '杨福敏',
                        '岳晓艳', '王鑫', '赵家琪', '蔺文婧', '钱宏翠', '蒋燕', '张莹', '郭晓津',
                        '丁小会', '潘红艳', '杨小灵', '张建强', '魏俊楠', '高红岩', '刘怀蔓', '周军藏', '黄雪玲']
NIGHT_YEAR2_TEACHERS = ['张光武', '徐玺怀', '魏婧', '李丽', '蒋桂芝', '贾明茂', '金小刚', '张文军',
                        '宿继忠', '王海燕', '金栋', '张瑞娟', '张玉婷', '张官军', '王俊英', '金翠凤',
                        '金红娟', '高佳宏', '齐科厚', '赵宗发', '金维晓', '张凯嘉', '张虹霞', '马小龙',
                        '张海龙', '杨正伟', '周亚楠', '张榕', '秦美玲', '金辉童', '赵满强', '隆亚丽',
                        '金万钟', '马文强', '杜玉斌', '曾赟']


def _semester_title(sem):
    """学期名 → 学年学期标题：2026-2027-1 → 2026—2027学年第一学期"""
    name = sem.name if sem else ''
    m = re.match(r'(\d{4})-(\d{4})-(\d)', name)
    if m:
        cn = {'1': '一', '2': '二', '3': '三'}.get(m.group(3), m.group(3))
        return '%s—%s学年第%s学期' % (m.group(1), m.group(2), cn)
    return name


def _rmb_upper(amount):
    """金额 → 人民币大写（如 60 → 陆拾元整）"""
    if amount is None:
        return ''
    try:
        amount = round(float(amount), 2)
    except Exception:
        return ''
    if amount == 0:
        return '零元整'
    digits = '零壹贰叁肆伍陆柒捌玖'
    units = ['', '拾', '佰', '仟']
    big_units = ['', '万', '亿']
    integer = int(amount)
    frac = int(round((amount - integer) * 100))
    if integer == 0:
        result = ''
    else:
        result = ''
        big_idx = 0
        while integer > 0:
            section = integer % 10000
            integer //= 10000
            section_str = ''
            zero_flag = False
            pos = 0
            while section > 0:
                digit = section % 10
                if digit == 0:
                    if section_str and not zero_flag:
                        section_str = '零' + section_str
                        zero_flag = True
                else:
                    section_str = digits[digit] + units[pos] + section_str
                    zero_flag = False
                section //= 10
                pos += 1
            if big_idx > 0 and section_str:
                section_str += big_units[big_idx]
            elif big_idx > 0 and result and not section_str:
                pass
            elif big_idx > 0 and not section_str and result:
                result = '零' + result
            result = section_str + result
            big_idx += 1
    if frac == 0:
        result += '元整'
    else:
        jiao = frac // 10
        fen = frac % 10
        if not result:
            result = '零元'
        if jiao:
            result += '元' if '元' not in result else ''
            result += digits[jiao] + '角'
        elif fen and '元' not in result:
            result += '元'
        if fen:
            result += digits[fen] + '分'
    return result


def _apply_uniform_style(ws, header_row=1):
    """给工作表套统一导出格式：宋体、细边框、居中；表头行宋体加粗"""
    from openpyxl.styles import Font, Alignment, Border, Side
    thin = Side(style='thin')
    border = Border(left=thin, top=thin, right=thin, bottom=thin)
    for row in ws.iter_rows():
        for c in row:
            c.font = Font(name='宋体', size=11)
            c.alignment = Alignment(horizontal='center', vertical='center')
            c.border = border
    for c in ws[header_row]:
        if c.value is not None:
            c.font = Font(name='宋体', size=12, bold=True)
    # 标题/说明行（表头之前）左对齐
    for r in range(1, header_row):
        for c in ws[r]:
            if c.value is not None and not isinstance(c.value, (int, float)):
                c.alignment = Alignment(horizontal='left', vertical='center')


def _night_stat_sheet(ws, title, period_str, grade_label, names, counts):
    """按教务处模板格式填充一个年级 sheet：标题/周期/年级/表头/名单/合计/大写/落款"""
    from openpyxl.styles import Font, Alignment, Border, Side
    thin = Side(style='thin')
    border = Border(left=thin, top=thin, right=thin, bottom=thin)
    center = Alignment(horizontal='center', vertical='center')
    left = Alignment(horizontal='left', vertical='center')
    n = len(names)
    total_row = 5 + n          # 表头4行 + n 个教师 → 合计行（与模板一致）
    upper_row = total_row + 1  # 大写行
    sign_row = upper_row + 1   # 落款行
    ws.merge_cells('A1:D1')
    ws['A1'] = title
    ws['A1'].font = Font(name='宋体', size=20, bold=True)
    ws['A1'].alignment = center
    ws.row_dimensions[1].height = 36.75
    ws['A2'] = period_str
    ws['A2'].font = Font(name='宋体', size=14)
    ws['A2'].alignment = center
    ws.row_dimensions[2].height = 23
    ws.merge_cells('A3:D3')
    ws['A3'] = grade_label
    ws['A3'].font = Font(name='宋体', size=14)
    ws['A3'].alignment = center
    ws.row_dimensions[3].height = 23
    headers = ['姓名', '跟班次数', '津贴（元）', '签名']
    for ci, h in enumerate(headers, 1):
        c = ws.cell(row=4, column=ci, value=h)
        c.font = Font(name='宋体', size=14)
        c.alignment = center
        c.border = border
    ws.row_dimensions[4].height = 22
    total_amt = 0.0
    for i, name in enumerate(names):
        r = 5 + i
        ws.cell(row=r, column=1, value=name).font = Font(name='宋体', size=12)
        ws.cell(row=r, column=1).alignment = center
        ws.cell(row=r, column=1).border = border
        cnt = counts.get(name)
        if cnt:
            amt = round(cnt * getattr(ws.parent, '_night_unit', 20), 2)
            total_amt += amt
            b = ws.cell(row=r, column=2, value=cnt)
            b.font = Font(name='宋体', size=14)
            b.alignment = center
            b.border = border
            c = ws.cell(row=r, column=3, value=amt)
            c.font = Font(name='宋体', size=14)
            c.alignment = center
            c.border = border
        for col in (2, 3, 4):
            cell = ws.cell(row=r, column=col)
            cell.border = border
            cell.alignment = center
        ws.row_dimensions[r].height = 24
    # 合计
    ws.cell(row=total_row, column=1, value='合计').font = Font(name='宋体', size=14)
    ws.cell(row=total_row, column=1).alignment = center
    ws.cell(row=total_row, column=1).border = border
    b = ws.cell(row=total_row, column=2, value='=SUM(B5:B%d)' % (4 + n))
    b.font = Font(name='宋体', size=14)
    b.alignment = center
    b.border = border
    c = ws.cell(row=total_row, column=3, value=round(total_amt, 2))
    c.font = Font(name='宋体', size=14); c.alignment = center; c.border = border
    ws.cell(row=total_row, column=4).border = border
    # 大写
    ws.merge_cells(start_row=upper_row, start_column=2, end_row=upper_row, end_column=4)
    ws.cell(row=upper_row, column=1, value='大写').font = Font(name='宋体', size=14)
    ws.cell(row=upper_row, column=1).alignment = center
    ws.cell(row=upper_row, column=1).border = border
    u = ws.cell(row=upper_row, column=2, value=_rmb_upper(total_amt))
    u.font = Font(name='宋体', size=14); u.alignment = center; u.border = border
    for col in (2, 3, 4):
        ws.cell(row=upper_row, column=col).border = border
    # 落款
    ws.merge_cells(start_row=sign_row, start_column=1, end_row=sign_row, end_column=4)
    ws.cell(row=sign_row, column=1, value='统计：                   审核：                     审批：').font = Font(name='宋体', size=12)
    ws.cell(row=sign_row, column=1).alignment = left
    # 列宽
    ws.column_dimensions['A'].width = 10.66
    ws.column_dimensions['B'].width = 17
    ws.column_dimensions['C'].width = 22.5
    ws.column_dimensions['D'].width = 13


def _night_stat_workbook(period, counts_y1, counts_y2, sem=None, unit=20):
    """生成夜自习津贴发放表 workbook（一年级/二年级 两个 sheet，教务处模板格式）"""
    from openpyxl import Workbook
    title = '%s夜自习津贴发放表' % _semester_title(sem)
    period_str = '%d-%d周' % ((period - 1) * 4 + 1, period * 4)
    wb = Workbook()
    for label, names, counts in [('一年级课任教师', NIGHT_YEAR1_TEACHERS, counts_y1),
                                 ('二年级课任教师', NIGHT_YEAR2_TEACHERS, counts_y2)]:
        ws = wb.active if label.startswith('一年级') else wb.create_sheet()
        ws.title = '一年级' if label.startswith('一年级') else '二年级'
        ws._night_unit = unit
        _night_stat_sheet(ws, title, period_str, label, names, counts)
    return wb


@app.route('/night/stats/export')
@login_required
def night_stats_export():
    """夜自习统计导出（教务处模板格式：一年级/二年级 两张表）"""
    sid = get_current_semester_id()
    pno = request.args.get('period', '')
    pno = int(pno) if pno.isdigit() else 1
    sem = db.session.get(Semester, sid) if sid else None
    pr = _period_range(sid, pno)
    unit = get_setting_float('night_shift_unit_price', 0)
    counts_y1 = {}
    counts_y2 = {}
    if pr and sem:
        shifts = NightShift.query.filter_by(semester_id=sid) \
            .filter(NightShift.status != 'absent') \
            .filter(NightShift.shift_date >= pr[1], NightShift.shift_date <= pr[2]).all()
        for s in shifts:
            name = teacher_name(s.teacher_id)
            if name in NIGHT_YEAR1_TEACHERS:
                counts_y1[name] = counts_y1.get(name, 0) + 1
            elif name in NIGHT_YEAR2_TEACHERS:
                counts_y2[name] = counts_y2.get(name, 0) + 1
    wb = _night_stat_workbook(pno, counts_y1, counts_y2, sem, unit)
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name='夜自习统计%d-%d周.xlsx' % ((pno - 1) * 4 + 1, pno * 4),
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/')
@login_required
def index():
    sid = get_current_semester_id()
    user = db.session.get(User, session.get('user_id'))
    stats = {}
    todos = []
    if sid:
        stats['classes'] = ClassInfo.query.filter_by(semester_id=sid).count()
        stats['teachers'] = Teacher.query.filter_by(semester_id=sid, is_active=True).count()
        stats['courses'] = Course.query.filter_by(semester_id=sid).count()
        stats['rooms'] = Classroom.query.filter_by(semester_id=sid).count()
        stats['textbooks'] = Textbook.query.filter_by(semester_id=sid).count()
        stats['tasks'] = TeachingTask.query.filter_by(semester_id=sid).count()
        stats['cells'] = ScheduleCell.query.filter_by(semester_id=sid).count()
        stats['pending_leaves'] = LeaveRequest.query.filter_by(semester_id=sid).count()
        stats['night_week'] = 0
        try:
            sem = db.session.get(Semester, sid) if sid else None
            if sem:
                today = date.today()
                wstart = today - timedelta(days=(today.weekday() + 1) % 7)
                wend = wstart + timedelta(days=4)
                stats['night_week'] = NightShift.query.filter_by(semester_id=sid) \
                    .filter(NightShift.shift_date >= wstart, NightShift.shift_date <= wend).count()
        except Exception:
            pass
        stats['orders_draft'] = OrderPlan.query.filter_by(semester_id=sid, status='draft').count()
        stats['issues'] = BookIssue.query.filter_by(semester_id=sid).count()
        stats['holidays'] = Holiday.query.filter_by(semester_id=sid).count()
        stats['overtimes'] = Overtime.query.filter_by(semester_id=sid).count()
        stats['fees'] = ManagementFee.query.filter_by(semester_id=sid).count()
        stats['ot_amount'] = round(sum((x.amount or 0) for x in Overtime.query.filter_by(semester_id=sid).all()), 2)
        stats['fee_amount'] = round(sum((x.amount or 0) for x in ManagementFee.query.filter_by(semester_id=sid).all()), 2)
        # 待办事项
        cls_all = ClassInfo.query.filter_by(semester_id=sid).count()
        cls_sched = len({c.class_id for c in ScheduleCell.query.filter_by(semester_id=sid).all()})
        no_sched = cls_all - cls_sched
        if no_sched > 0:
            todos.append(('班级无课表', '%d 个班' % no_sched, '/schedule', 'fas fa-table'))
        no_room = ClassInfo.query.filter_by(semester_id=sid).filter(ClassInfo.classroom_id.is_(None)).count()
        if no_room > 0:
            todos.append(('未设本班教室', '%d 个班' % no_room, '/classes', 'fas fa-door-open'))
        n = OrderPlan.query.filter_by(semester_id=sid).filter(OrderPlan.status != 'arrived').count()
        if n:
            todos.append(('征订未到货', '%d 条' % n, '/orders', 'fas fa-truck'))
        m = date.today().strftime('%Y-%m')
        n = NightShift.query.filter_by(semester_id=sid, status='scheduled') \
            .filter(NightShift.shift_date.like(m + '%')).count()
        if n:
            todos.append(('本月夜自习待确认', '%d 条' % n, '/night', 'fas fa-moon'))
    return render_template('index.html', stats=stats, todos=todos, user=user)

# ══════════════════════════════════════════════
# 学期管理
# ══════════════════════════════════════════════

@app.route('/semester/add', methods=['POST'])
@admin_required
def semester_add():
    start_year = request.form.get('start_year', '').strip()
    sem_num = request.form.get('sem_num', request.form.get('semester_num', '1')).strip()
    start_date = request.form.get('start_date', '').strip()
    end_date = request.form.get('end_date', '').strip()
    if not re.match(r'^\d{4}$', start_year):
        flash('学年起始年格式错误')
        return redirect(url_for('index'))
    end_year = str(int(start_year) + 1)
    name = f'{start_year}-{end_year}学年度第{sem_num}学期'
    try:
        sd = datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else date.today()
        ed = datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else sd + timedelta(days=180)
    except Exception:
        flash('日期格式错误')
        return redirect(url_for('index'))
    s = Semester(name=name, start_date=sd, end_date=ed)
    db.session.add(s)
    db.session.flush()
    # 继承源学期数据（可选）
    inherit_from = request.form.get('inherit_from', '').strip()
    types = request.form.getlist('inherit_types')
    if inherit_from.isdigit():
        src = db.session.get(Semester, int(inherit_from))
        if src and src.id != s.id:
            n = _inherit_semester_data(s.id, src, types)
            if n:
                flash(f'学期「{name}」创建成功，已从「{src.name}」继承 {n} 类数据')
            else:
                flash(f'学期「{name}」创建成功（未勾选继承内容）')
        else:
            flash(f'学期「{name}」创建成功')
    else:
        flash(f'学期「{name}」创建成功')
    db.session.commit()
    session['semester_id'] = s.id
    return redirect(url_for('index'))


def _inherit_semester_data(new_sid, src, types):
    """把源学期数据复制到新学期（仅复制，不动源数据）。返回继承的数据类数。
    关联自动重映射：教材→新课程、任务→新班级/课程/教师/教室、课表→新任务等。"""
    types = set(types)
    id_map = {}
    done = 0

    if 'classes' in types:
        for c in ClassInfo.query.filter_by(semester_id=src.id).all():
            nc = ClassInfo(semester_id=new_sid, name=c.name, grade=c.grade,
                           head_teacher=c.head_teacher, student_count=c.student_count, remark=c.remark)
            db.session.add(nc)
            db.session.flush()
            id_map[('class', c.id)] = nc.id
        if id_map:
            done += 1
    if 'teachers' in types:
        for t in Teacher.query.filter_by(semester_id=src.id).all():
            nt = Teacher(semester_id=new_sid, name=t.name, position=t.position,
                         subject_category=t.subject_category, phone=t.phone,
                         is_active=t.is_active, remark=t.remark)
            db.session.add(nt)
            db.session.flush()
            id_map[('teacher', t.id)] = nt.id
        if any(k[0] == 'teacher' for k in id_map):
            done += 1
    if 'courses' in types:
        for c in Course.query.filter_by(semester_id=src.id).all():
            nc = Course(semester_id=new_sid, name=c.name, category=c.category,
                        default_weekly_hours=c.default_weekly_hours, remark=c.remark)
            db.session.add(nc)
            db.session.flush()
            id_map[('course', c.id)] = nc.id
        if any(k[0] == 'course' for k in id_map):
            done += 1
    if 'classrooms' in types:
        for r in Classroom.query.filter_by(semester_id=src.id).all():
            nr = Classroom(semester_id=new_sid, name=r.name, building=r.building, room_no=r.room_no,
                           ctype=r.ctype, capacity=r.capacity, remark=r.remark)
            db.session.add(nr)
            db.session.flush()
            id_map[('room', r.id)] = nr.id
        if any(k[0] == 'room' for k in id_map):
            done += 1
    if 'textbooks' in types:
        for b in Textbook.query.filter_by(semester_id=src.id).all():
            nb = Textbook(semester_id=new_sid, name=b.name, isbn=b.isbn, publisher=b.publisher,
                          author=b.author, price=b.price, version=b.version,
                          course_id=id_map.get(('course', b.course_id)) if b.course_id else None,
                          stock=b.stock, remark=b.remark)
            db.session.add(nb)
            db.session.flush()
            id_map[('book', b.id)] = nb.id
        if any(k[0] == 'book' for k in id_map):
            done += 1
    if 'tasks' in types:
        for t in TeachingTask.query.filter_by(semester_id=src.id).all():
            # 依赖映射必须齐全（班级/课程/教师），缺失则跳过该任务，避免悬空引用
            new_cids = [id_map[('class', x)] for x in t.classes() if ('class', x) in id_map]
            new_course = id_map.get(('course', t.course_id))
            new_teacher = id_map.get(('teacher', t.teacher_id))
            if not new_cids or not new_course or not new_teacher:
                continue
            nt = TeachingTask(semester_id=new_sid, class_ids=json.dumps(new_cids),
                              course_id=new_course, teacher_id=new_teacher,
                              weekly_hours=t.weekly_hours,
                              classroom_id=id_map.get(('room', t.classroom_id)) if t.classroom_id else None,
                              week_type=t.week_type, remark=t.remark)
            db.session.add(nt)
            db.session.flush()
            id_map[('task', t.id)] = nt.id
        if any(k[0] == 'task' for k in id_map):
            done += 1
    if 'schedule' in types:
        for c in ScheduleCell.query.filter_by(semester_id=src.id).all():
            # 依赖映射必须齐全（班级/课程/教师），缺失则跳过该格子
            new_class_id = id_map.get(('class', c.class_id))
            new_course = id_map.get(('course', c.course_id))
            new_teacher = id_map.get(('teacher', c.teacher_id))
            if not new_class_id or not new_course or not new_teacher:
                continue
            db.session.add(ScheduleCell(semester_id=new_sid,
                                        task_id=id_map.get(('task', c.task_id)) if c.task_id else None,
                                        class_id=new_class_id, weekday=c.weekday, period=c.period,
                                        course_id=new_course, teacher_id=new_teacher,
                                        classroom_id=id_map.get(('room', c.classroom_id)) if c.classroom_id else None,
                                        week_type=c.week_type))
        if ScheduleCell.query.filter_by(semester_id=new_sid).count():
            done += 1
    return done

@app.route('/semester/set', methods=['POST'])
@app.route('/semester/<int:sid>/set', methods=['POST'])
@admin_required
def semester_set(sid=None):
    if sid is None:
        try:
            sid = int(request.form.get('semester_id', 0) or 0)
        except Exception:
            sid = 0
    s = db.session.get(Semester, sid) if sid else None
    if not s:
        flash('学期不存在')
    else:
        session['semester_id'] = s.id
        flash(f'已切换到「{s.name}」')
    return redirect(request.referrer or url_for('index'))

@app.route('/semester/<int:sid>/rename', methods=['POST'])
@admin_required
def semester_rename(sid):
    s = db.session.get(Semester, sid) if sid else None
    if not s:
        flash('学期不存在')
        return redirect(url_for('index'))
    name = request.form.get('name', '').strip()
    if not name:
        flash('名称不能为空')
    else:
        s.name = name
        db.session.commit()
        flash('学期已重命名')
    return redirect(request.referrer or url_for('index'))

@app.route('/semester/<int:sid>/edit', methods=['POST'])
@admin_required
def semester_edit(sid):
    s = db.session.get(Semester, sid) if sid else None
    if not s:
        flash('学期不存在')
        return redirect(url_for('index'))
    try:
        sd = datetime.strptime(request.form.get('start_date', ''), '%Y-%m-%d').date()
        ed = datetime.strptime(request.form.get('end_date', ''), '%Y-%m-%d').date()
        s.start_date, s.end_date = sd, ed
    except Exception:
        flash('日期格式错误')
        return redirect(url_for('index'))
    tw = request.form.get('teaching_weeks', '').strip()
    s.teaching_weeks = int(tw) if re.match(r'^\d+$', tw) else None
    db.session.commit()
    flash('学期信息已更新')
    return redirect(request.referrer or url_for('index'))

@app.route('/semester/<int:sid>/delete', methods=['POST'])
@admin_required
def semester_delete(sid):
    s = db.session.get(Semester, sid) if sid else None
    if not s:
        flash('学期不存在')
        return redirect(url_for('index'))
    if Semester.query.count() <= 1:
        flash('至少保留一个学期')
        return redirect(url_for('index'))
    # 级联删除所有关联数据（子→父顺序）
    for m in (ScheduleCell, TeachingTask, BookIssue, OrderPlan, NightShift,
              LeaveRequest, Overtime, ManagementFee, Holiday):
        m.query.filter_by(semester_id=sid).delete()
    ClassInfo.query.filter_by(semester_id=sid).delete()
    Teacher.query.filter_by(semester_id=sid).delete()
    Course.query.filter_by(semester_id=sid).delete()
    Classroom.query.filter_by(semester_id=sid).delete()
    Textbook.query.filter_by(semester_id=sid).delete()
    db.session.delete(s)
    db.session.commit()
    if session.get('semester_id') == sid:
        session.pop('semester_id', None)
        get_current_semester_id()
    flash('学期及其数据已删除')
    return redirect(url_for('index'))

# ══════════════════════════════════════════════
# 基础数据：班级 / 教师 / 课程 / 教室 / 教材库
# ══════════════════════════════════════════════

@app.route('/classes')
@login_required
def classes_page():
    q = ClassInfo.query.filter_by(semester_id=get_current_semester_id())
    g = request.args.get('grade', '').strip()
    if g:
        q = q.filter(ClassInfo.grade == g)
    rows, total, page, pages, qs = paginate(q.order_by(ClassInfo.name))
    base = ClassInfo.query.filter_by(semester_id=get_current_semester_id())
    grades = [x[0] for x in db.session.query(ClassInfo.grade).distinct().all() if x[0]]
    stats = {'total': base.count()}
    for gd in grades:
        stats[gd] = base.filter_by(grade=gd).count()
    rooms = sem_filter(Classroom.query).order_by(Classroom.name).all() if get_current_semester_id() else []
    return render_template('classes.html', rows=rows, total=total, page=page, pages=pages,
                           qs=qs, g=g, grades=grades, stats=stats, rooms=rooms)

@app.route('/classes/add', methods=['POST'])
@admin_required
def classes_add():
    name = request.form.get('name', '').strip()
    if not name:
        flash('班级名称不能为空')
        return redirect(request.referrer or url_for('classes_page'))
    c = ClassInfo(semester_id=get_current_semester_id(), name=name,
                  grade=request.form.get('grade', '').strip(),
                  head_teacher=request.form.get('head_teacher', '').strip(),
                  student_count=int(request.form.get('student_count', 0) or 0),
                  classroom_id=int(request.form.get('classroom_id', 0) or 0) or None,
                  remark=request.form.get('remark', '').strip())
    db.session.add(c)
    db.session.commit()
    flash('班级已添加')
    return redirect(url_for('classes_page'))

@app.route('/classes/<int:cid>/edit', methods=['POST'])
@admin_required
def classes_edit(cid):
    c = db.session.get(ClassInfo, cid)
    if not c:
        flash('班级不存在')
        return redirect(url_for('classes_page'))
    c.name = request.form.get('name', c.name).strip()
    c.grade = request.form.get('grade', '').strip()
    c.head_teacher = request.form.get('head_teacher', '').strip()
    try:
        c.student_count = int(request.form.get('student_count', 0) or 0)
    except Exception:
        pass
    c.remark = request.form.get('remark', '').strip()
    try:
        c.classroom_id = int(request.form.get('classroom_id', 0) or 0) or None
    except Exception:
        pass
    db.session.commit()
    flash('班级已更新')
    return redirect(url_for('classes_page'))

@app.route('/classes/<int:cid>/delete', methods=['POST'])
@admin_required
def classes_delete(cid):
    c = db.session.get(ClassInfo, cid)
    if not c:
        flash('班级不存在')
        return redirect(url_for('classes_page'))
    n = _ref_count('class', cid)
    if n:
        flash(f'该班级被 {n} 条业务记录引用（课表/任务/发书等），请先删除或调整相关记录')
        return redirect(url_for('classes_page'))
    db.session.delete(c)
    db.session.commit()
    flash('班级已删除')
    return redirect(url_for('classes_page'))

# ── 教师 ──

_SUBJECT_ORDER = ['语文', '数学', '英语', '政治', '体育', '历史', '计算机']


def _teacher_subject_rank(sid, tid):
    """教师任教科目排序：语文→数学→英语→政治→体育→历史→计算机→专业课→其他专业课"""
    courses = db.session.query(Course.name, Course.category).join(
        ScheduleCell, ScheduleCell.course_id == Course.id) \
        .filter(ScheduleCell.semester_id == sid, ScheduleCell.teacher_id == tid).distinct().all()
    if not courses:
        return len(_SUBJECT_ORDER) + 1
    for i, kw in enumerate(_SUBJECT_ORDER):
        if any(kw in (name or '') for name, _ in courses):
            return i
    if any(cat == '专业课' for _, cat in courses):
        return len(_SUBJECT_ORDER)
    return len(_SUBJECT_ORDER) + 1


@app.route('/teachers')
@login_required
def teachers_page():
    sid = get_current_semester_id()
    q = Teacher.query.filter_by(semester_id=sid)
    kw = request.args.get('kw', '').strip()
    pos = request.args.get('position', '').strip()
    cat = request.args.get('category', '').strip()
    act = request.args.get('active', '').strip()
    if kw:
        q = q.filter(Teacher.name.like('%' + kw + '%'))
    if pos:
        q = q.filter(Teacher.position == pos)
    if cat:
        q = q.filter(Teacher.subject_category == cat)
    if act:
        q = q.filter(Teacher.is_active == (act == '1'))
    rows, total, page, pages, qs = paginate(q.order_by(Teacher.name))
    # 按任教科目排序（语文→数学→英语→政治→体育→历史→计算机→专业课→其他专业课）
    rows = sorted(rows, key=lambda t: (_teacher_subject_rank(sid, t.id), t.name))
    base = Teacher.query.filter_by(semester_id=sid)
    stats = {
        'total': base.count(),
        'active': base.filter_by(is_active=True).count(),
        'culture': base.filter_by(subject_category='文化课').count(),
        'major': base.filter_by(subject_category='专业课').count(),
    }
    positions = [p for p, in db.session.query(Teacher.position).distinct().all() if p]
    return render_template('teachers.html', rows=rows, total=total, page=page, pages=pages,
                           qs=qs, kw=kw, pos=pos, cat=cat, act=act, positions=positions,
                           stats=stats)

@app.route('/teachers/add', methods=['POST'])
@admin_required
def teachers_add():
    name = request.form.get('name', '').strip()
    if not name:
        flash('教师姓名不能为空')
        return redirect(request.referrer or url_for('teachers_page'))
    t = Teacher(semester_id=get_current_semester_id(), name=name,
                position=request.form.get('position', '专任教师').strip() or '专任教师',
                subject_category=request.form.get('subject_category', '专业课').strip() or '专业课',
                phone=request.form.get('phone', '').strip(),
                remark=request.form.get('remark', '').strip())
    db.session.add(t)
    db.session.commit()
    flash('教师已添加')
    return redirect(url_for('teachers_page'))

@app.route('/teachers/<int:tid>/edit', methods=['POST'])
@admin_required
def teachers_edit(tid):
    t = db.session.get(Teacher, tid)
    if not t:
        flash('教师不存在')
        return redirect(url_for('teachers_page'))
    t.name = request.form.get('name', t.name).strip()
    t.position = request.form.get('position', '专任教师').strip() or '专任教师'
    t.subject_category = request.form.get('subject_category', '专业课').strip() or '专业课'
    t.phone = request.form.get('phone', '').strip()
    t.is_active = request.form.get('is_active') == 'on'
    t.remark = request.form.get('remark', '').strip()
    db.session.commit()
    flash('教师已更新')
    return redirect(url_for('teachers_page'))

@app.route('/teachers/<int:tid>/delete', methods=['POST'])
@admin_required
def teachers_delete(tid):
    t = db.session.get(Teacher, tid)
    if not t:
        flash('教师不存在')
        return redirect(url_for('teachers_page'))
    n = _ref_count('teacher', tid)
    if n:
        flash(f'该教师被 {n} 条业务记录引用（任务/课表/请假/夜自习/加班等），请先删除或调整相关记录')
        return redirect(url_for('teachers_page'))
    db.session.delete(t)
    db.session.commit()
    flash('教师已删除')
    return redirect(url_for('teachers_page'))

# ── 课程 ──

@app.route('/courses')
@login_required
def courses_page():
    sid = get_current_semester_id()
    q = Course.query.filter_by(semester_id=sid)
    # 合班课（名称含「合」）不单独显示
    q = q.filter(~Course.name.like('%合%'))
    cat = request.args.get('category', '').strip()
    if cat:
        q = q.filter(Course.category == cat)
    rows, total, page, pages, qs = paginate(q.order_by(Course.name))
    base = Course.query.filter_by(semester_id=sid)
    cats = [x[0] for x in db.session.query(Course.category).distinct().all() if x[0]]
    stats = {'total': base.count()}
    for c in cats:
        stats[c] = base.filter_by(category=c).count()
    return render_template('courses.html', rows=rows, total=total, page=page, pages=pages,
                           qs=qs, cat=cat, cats=cats, stats=stats)

@app.route('/courses/add', methods=['POST'])
@admin_required
def courses_add():
    name = request.form.get('name', '').strip()
    if not name:
        flash('课程名称不能为空')
        return redirect(request.referrer or url_for('courses_page'))
    c = Course(semester_id=get_current_semester_id(), name=name,
               category=request.form.get('category', '专业课').strip() or '专业课',
               default_weekly_hours=int(request.form.get('default_weekly_hours', 4) or 4),
               remark=request.form.get('remark', '').strip())
    db.session.add(c)
    db.session.commit()
    flash('课程已添加')
    return redirect(url_for('courses_page'))

@app.route('/courses/<int:cid>/edit', methods=['POST'])
@admin_required
def courses_edit(cid):
    c = db.session.get(Course, cid)
    if not c:
        flash('课程不存在')
        return redirect(url_for('courses_page'))
    c.name = request.form.get('name', c.name).strip()
    c.category = request.form.get('category', '专业课').strip() or '专业课'
    try:
        c.default_weekly_hours = int(request.form.get('default_weekly_hours', 4) or 4)
    except Exception:
        pass
    c.remark = request.form.get('remark', '').strip()
    db.session.commit()
    flash('课程已更新')
    return redirect(url_for('courses_page'))

@app.route('/courses/<int:cid>/delete', methods=['POST'])
@admin_required
def courses_delete(cid):
    c = db.session.get(Course, cid)
    if not c:
        flash('课程不存在')
        return redirect(url_for('courses_page'))
    n = _ref_count('course', cid)
    if n:
        flash(f'该课程被 {n} 条业务记录引用（任务/课表/教材等），请先删除或调整相关记录')
        return redirect(url_for('courses_page'))
    db.session.delete(c)
    db.session.commit()
    flash('课程已删除')
    return redirect(url_for('courses_page'))

# ── 教室 ──

@app.route('/classrooms')
@login_required
def classrooms_page():
    sid = get_current_semester_id()
    q = Classroom.query.filter_by(semester_id=sid)
    ct = request.args.get('ctype', '').strip()
    kw = request.args.get('kw', '').strip()
    if ct:
        q = q.filter(Classroom.ctype == ct)
    if kw:
        q = q.filter(Classroom.name.like('%' + kw + '%'))
    rows, total, page, pages, qs = paginate(q.order_by(Classroom.name))
    base = Classroom.query.filter_by(semester_id=sid)
    # 教室 ↔ 班级对应：非机房教室的门牌号对应一个班级（本班教室），显示在备注
    room_class = {}
    for c in ClassInfo.query.filter_by(semester_id=sid).all():
        if c.classroom_id:
            room_class[c.classroom_id] = c.name
    ctypes = [x[0] for x in db.session.query(Classroom.ctype).distinct().all() if x[0]]
    stats = {'total': base.count()}
    for c in ctypes:
        stats[c] = base.filter_by(ctype=c).count()
    return render_template('classrooms.html', rows=rows, total=total, page=page, pages=pages,
                           qs=qs, ct=ct, kw=kw, ctypes=ctypes, stats=stats,
                           room_class=room_class)

@app.route('/classrooms/add', methods=['POST'])
@admin_required
def classrooms_add():
    building = request.form.get('building', '').strip()
    room_no = request.form.get('room_no', '').strip()
    name = building + room_no
    if not name:
        flash('楼名或门牌号至少填写一项')
        return redirect(request.referrer or url_for('classrooms_page'))
    c = Classroom(semester_id=get_current_semester_id(), name=name,
                  building=building, room_no=room_no,
                  ctype=request.form.get('ctype', '普通教室').strip() or '普通教室',
                  capacity=int(request.form.get('capacity', 50) or 50),
                  remark=request.form.get('remark', '').strip())
    db.session.add(c)
    db.session.commit()
    flash('教室已添加')
    return redirect(url_for('classrooms_page'))

@app.route('/classrooms/<int:cid>/edit', methods=['POST'])
@admin_required
def classrooms_edit(cid):
    c = db.session.get(Classroom, cid)
    if not c:
        flash('教室不存在')
        return redirect(url_for('classrooms_page'))
    building = request.form.get('building', c.building or '').strip()
    room_no = request.form.get('room_no', c.room_no or '').strip()
    new_name = building + room_no
    if new_name:
        c.name = new_name
    c.building = building
    c.room_no = room_no
    c.ctype = request.form.get('ctype', '普通教室').strip() or '普通教室'
    try:
        c.capacity = int(request.form.get('capacity', 50) or 50)
    except Exception:
        pass
    c.remark = request.form.get('remark', '').strip()
    db.session.commit()
    flash('教室已更新')
    return redirect(url_for('classrooms_page'))

@app.route('/classrooms/<int:cid>/delete', methods=['POST'])
@admin_required
def classrooms_delete(cid):
    c = db.session.get(Classroom, cid)
    if not c:
        flash('教室不存在')
        return redirect(url_for('classrooms_page'))
    n = _ref_count('room', cid)
    if n:
        flash(f'该教室被 {n} 条业务记录引用（任务/课表），请先调整相关记录')
        return redirect(url_for('classrooms_page'))
    db.session.delete(c)
    db.session.commit()
    flash('教室已删除')
    return redirect(url_for('classrooms_page'))

# ── 教材库 ──

@app.route('/textbooks')
@login_required
def textbooks_page():
    rows = sem_filter(Textbook.query).order_by(Textbook.name).all()
    courses = sem_filter(Course.query).order_by(Course.name).all()
    return render_template('textbooks.html', rows=rows, courses=courses)

@app.route('/textbooks/add', methods=['POST'])
@admin_required
def textbooks_add():
    name = request.form.get('name', '').strip()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if not name:
        if is_ajax:
            return jsonify({'ok': False, 'error': '教材名称不能为空'})
        flash('教材名称不能为空')
        return redirect(request.referrer or url_for('textbooks_page'))
    try:
        price = float(request.form.get('price', 0) or 0)
        stock = int(request.form.get('stock', 0) or 0)
    except Exception:
        price, stock = 0, 0
    t = Textbook(semester_id=get_current_semester_id(), name=name,
                 isbn=request.form.get('isbn', '').strip(),
                 publisher=request.form.get('publisher', '').strip(),
                 author=request.form.get('author', '').strip(),
                 price=price, version=request.form.get('version', '').strip(),
                 course_id=int(request.form.get('course_id') or 0) or None,
                 stock=stock, remark=request.form.get('remark', '').strip())
    db.session.add(t)
    db.session.commit()
    if is_ajax:
        return jsonify({'ok': True, 'id': t.id, 'name': t.name, 'price': t.price})
    flash('教材已添加')
    return redirect(url_for('textbooks_page'))

@app.route('/textbooks/<int:tid>/edit', methods=['POST'])
@admin_required
def textbooks_edit(tid):
    t = db.session.get(Textbook, tid)
    if not t:
        flash('教材不存在')
        return redirect(url_for('textbooks_page'))
    t.name = request.form.get('name', t.name).strip()
    t.isbn = request.form.get('isbn', '').strip()
    t.publisher = request.form.get('publisher', '').strip()
    t.author = request.form.get('author', '').strip()
    try:
        t.price = float(request.form.get('price', 0) or 0)
    except Exception:
        pass
    t.version = request.form.get('version', '').strip()
    try:
        t.course_id = int(request.form.get('course_id') or 0) or None
    except Exception:
        pass
    t.remark = request.form.get('remark', '').strip()
    db.session.commit()
    flash('教材已更新')
    return redirect(url_for('textbooks_page'))

@app.route('/textbooks/<int:tid>/stock', methods=['GET', 'POST'])
@admin_required
def textbook_stock(tid):
    """教材出入库流水：查看 + 手动入库"""
    tb = db.session.get(Textbook, tid)
    if not tb:
        flash('教材不存在')
        return redirect(url_for('textbooks_page'))
    if request.method == 'POST':
        try:
            qty = int(request.form.get('qty', 0) or 0)
        except Exception:
            qty = 0
        if qty <= 0:
            flash('入库数量必须大于0')
            return redirect(request.referrer or url_for('textbook_stock', tid=tid))
        tb.stock = (tb.stock or 0) + qty
        db.session.add(BookStockLog(semester_id=get_current_semester_id(), textbook_id=tb.id,
                                    change_type='in', qty=qty,
                                    note=request.form.get('note', '手动入库').strip() or '手动入库'))
        db.session.commit()
        flash('已入库 %d 本，当前库存 %d 本' % (qty, tb.stock or 0))
        return redirect(url_for('textbook_stock', tid=tid))
    logs = BookStockLog.query.filter_by(semester_id=get_current_semester_id(), textbook_id=tb.id) \
        .order_by(BookStockLog.id.desc()).all()
    total_in = sum(x.qty for x in logs if x.change_type == 'in')
    total_out = sum(x.qty for x in logs if x.change_type == 'out')
    return render_template('textbook_stock.html', tb=tb, logs=logs,
                           total_in=total_in, total_out=total_out)


@app.route('/textbooks/<int:tid>/delete', methods=['POST'])
@admin_required
def textbooks_delete(tid):
    t = db.session.get(Textbook, tid)
    if not t:
        flash('教材不存在')
        return redirect(url_for('textbooks_page'))
    n = _ref_count('textbook', tid)
    if n:
        flash(f'该教材被 {n} 条业务记录引用（征订/发书），请先删除或调整相关记录')
        return redirect(url_for('textbooks_page'))
    db.session.delete(t)
    db.session.commit()
    flash('教材已删除')
    return redirect(url_for('textbooks_page'))

# ══════════════════════════════════════════════
# 订书、发书管理
# ══════════════════════════════════════════════

@app.route('/orders')
@login_required
def orders_page():
    sid = get_current_semester_id()
    q = OrderPlan.query.filter_by(semester_id=sid)
    major = request.args.get('major', '').strip()
    s_no = request.args.get('semester_no', '').strip()
    cat = request.args.get('cat', '').strip()
    if cat == 'culture':
        # 文化课：无专业（全校各班）
        q = q.filter((OrderPlan.major == '') | (OrderPlan.major.is_(None)))
    elif cat == 'major':
        # 专业课：有专业归属
        q = q.filter(OrderPlan.major != '')
    if major:
        q = q.filter(OrderPlan.major == major)
    if s_no.isdigit():
        q = q.filter(OrderPlan.semester_no == int(s_no))
    rows = q.order_by(OrderPlan.major, OrderPlan.semester_no, OrderPlan.created_at.desc()).all()
    courses = sem_filter(Course.query).order_by(Course.name).all()
    textbooks = sem_filter(Textbook.query).order_by(Textbook.name).all()
    classes = sem_filter(ClassInfo.query).order_by(ClassInfo.name).all()
    majors = [x[0] for x in db.session.query(OrderPlan.major).distinct().all() if x[0]]
    return render_template('orders.html', rows=rows, courses=courses,
                           textbooks=textbooks, classes=classes, major=major,
                           s_no=s_no, majors=majors, cat=cat)

@app.route('/orders/add', methods=['POST'])
@admin_required
def orders_add():
    textbook_id = request.form.get('textbook_id', '').strip()
    if not textbook_id or not textbook_id.isdigit():
        flash('请选择教材')
        return redirect(request.referrer or url_for('orders_page'))
    try:
        quantity = int(request.form.get('quantity', 0) or 0)
        unit_price = float(request.form.get('unit_price', 0) or 0)
    except Exception:
        quantity, unit_price = 0, 0
    tb = db.session.get(Textbook, int(textbook_id))
    if not tb:
        flash('教材不存在')
        return redirect(url_for('orders_page'))
    if not unit_price:
        unit_price = tb.price
    # 图书类别：culture=文化课（全校各班）/ major=专业课（按专业）
    book_type = request.form.get('book_type', 'culture')
    major = request.form.get('major', '').strip()
    class_id = request.form.get('class_id', '').strip()
    if book_type == 'major':
        if not major:
            flash('专业课征订必须填写专业')
            return redirect(request.referrer or url_for('orders_page'))
        class_id = int(class_id) if class_id.isdigit() else None
    else:
        # 文化课：每个班级都有 → 不指定专业、范围=全校
        major = ''
        class_id = None
    o = OrderPlan(semester_id=get_current_semester_id(),
                  course_id=int(request.form.get('course_id') or 0) or None,
                  textbook_id=tb.id,
                  class_id=class_id,
                  major=major,
                  semester_no=int(request.form.get('semester_no') or 1) or 1,
                  quantity=quantity, unit_price=unit_price,
                  remark=request.form.get('remark', '').strip())
    db.session.add(o)
    db.session.commit()
    flash('征订计划已添加')
    return redirect(url_for('orders_page'))

@app.route('/orders/<int:oid>/status', methods=['POST'])
@admin_required
def orders_status(oid):
    o = db.session.get(OrderPlan, oid)
    if not o:
        flash('计划不存在')
        return redirect(url_for('orders_page'))
    st = request.form.get('status', '')
    if st in ('draft', 'approved', 'arrived'):
        o.status = st
        db.session.commit()
        flash('状态已更新')
    return redirect(url_for('orders_page'))

@app.route('/orders/<int:oid>/delete', methods=['POST'])
@admin_required
def orders_delete(oid):
    o = db.session.get(OrderPlan, oid)
    if not o:
        flash('计划不存在')
        return redirect(url_for('orders_page'))
    db.session.delete(o)
    db.session.commit()
    flash('征订计划已删除')
    return redirect(url_for('orders_page'))

@app.route('/issues')
@login_required
def issues_page():
    rows = sem_filter(BookIssue.query).order_by(BookIssue.issue_date.desc()).all()
    textbooks = sem_filter(Textbook.query).order_by(Textbook.name).all()
    classes = sem_filter(ClassInfo.query).order_by(ClassInfo.name).all()
    teachers = sem_filter(Teacher.query).order_by(Teacher.name).all()
    return render_template('issues.html', rows=rows, textbooks=textbooks,
                           classes=classes, teachers=teachers)

@app.route('/issues/add', methods=['POST'])
@admin_required
def issues_add():
    issue_type = request.form.get('issue_type', 'class')
    textbook_id = request.form.get('textbook_id', '').strip()
    if not textbook_id or not textbook_id.isdigit():
        flash('请选择教材')
        return redirect(request.referrer or url_for('issues_page'))
    try:
        quantity = int(request.form.get('quantity', 0) or 0)
    except Exception:
        quantity = 0
    tb = db.session.get(Textbook, int(textbook_id))
    if not tb:
        flash('教材不存在')
        return redirect(url_for('issues_page'))
    try:
        issue_date = datetime.strptime(request.form.get('issue_date', ''), '%Y-%m-%d').date() if request.form.get('issue_date') else date.today()
    except Exception:
        issue_date = date.today()
    # 班级发书按在籍人数快捷填入数量（class_id/teacher_id 非法值按 None 处理）
    if issue_type == 'class':
        _cid = request.form.get('class_id', '').strip()
        class_id = int(_cid) if _cid.isdigit() else None
        teacher_id = None
        if quantity <= 0 and class_id:
            c = db.session.get(ClassInfo, class_id)
            if c:
                quantity = c.student_count
    else:
        _tid = request.form.get('teacher_id', '').strip()
        teacher_id = int(_tid) if _tid.isdigit() else None
        if not teacher_id:
            flash('教师教本需选择教师')
            return redirect(request.referrer or url_for('issues_page'))
        class_id = None
        if quantity <= 0:
            quantity = 1
    if quantity <= 0:
        flash('数量必须大于0')
        return redirect(request.referrer or url_for('issues_page'))
    # 库存校验：发书数量不能超过库存
    if tb.stock is not None and quantity > (tb.stock or 0):
        flash('库存不足：教材「%s」库存 %d 本，本次发 %d 本' % (tb.name, tb.stock or 0, quantity))
        return redirect(request.referrer or url_for('issues_page'))
    # 重复发书拦截：同班级 + 同教材已有发书记录
    if issue_type == 'class' and class_id:
        dup = BookIssue.query.filter_by(semester_id=get_current_semester_id(),
                                        issue_type='class', class_id=class_id,
                                        textbook_id=tb.id).first()
        if dup:
            flash('「%s」已给该班发过此书（%s 本），如需补发请删除原记录或调整数量' % (tb.name, dup.quantity))
            return redirect(request.referrer or url_for('issues_page'))
    i = BookIssue(semester_id=get_current_semester_id(), issue_type=issue_type,
                  class_id=class_id, teacher_id=teacher_id, textbook_id=tb.id,
                  quantity=quantity, signer=request.form.get('signer', '').strip(),
                  issue_date=issue_date, remark=request.form.get('remark', '').strip())
    db.session.add(i)
    # 自动扣减库存 + 出库流水
    if tb.stock is not None:
        tb.stock = (tb.stock or 0) - quantity
    db.session.add(BookStockLog(semester_id=get_current_semester_id(), textbook_id=tb.id,
                                change_type='out', qty=quantity,
                                note='发书：%s' % (class_name(class_id) if class_id else '教师教本')))
    db.session.commit()
    flash('发书记录已添加（库存剩余 %d 本）' % (tb.stock or 0))
    return redirect(url_for('issues_page'))

@app.route('/issues/<int:iid>/delete', methods=['POST'])
@admin_required
def issues_delete(iid):
    i = db.session.get(BookIssue, iid)
    if not i:
        flash('记录不存在')
        return redirect(url_for('issues_page'))
    # 回补库存 + 冲正流水（防止误删后库存永久缺失）
    tb = db.session.get(Textbook, i.textbook_id)
    if tb:
        tb.stock = (tb.stock or 0) + i.quantity
        db.session.add(BookStockLog(semester_id=i.semester_id, textbook_id=tb.id,
                                    change_type='in', qty=i.quantity,
                                    note='删除发书冲正：%s' % (class_name(i.class_id) if i.class_id else '教师教本')))
    db.session.delete(i)
    db.session.commit()
    flash('发书记录已删除，库存已回补' + ('（剩余 %d 本）' % (tb.stock or 0) if tb else ''))
    return redirect(url_for('issues_page'))

@app.route('/orders/export')
@login_required
def orders_export():
    """订书计划导出：空=全部专业，major 指定=分专业导出；cat=culture/major 按图书类别"""
    sid = get_current_semester_id()
    major = request.args.get('major', '').strip()
    s_no = request.args.get('semester_no', '').strip()
    cat = request.args.get('cat', '').strip()
    q = OrderPlan.query.filter_by(semester_id=sid)
    if cat == 'culture':
        q = q.filter((OrderPlan.major == '') | (OrderPlan.major.is_(None)))
    elif cat == 'major':
        q = q.filter(OrderPlan.major != '')
    if major:
        q = q.filter(OrderPlan.major == major)
    if s_no.isdigit():
        q = q.filter(OrderPlan.semester_no == int(s_no))
    rows = q.order_by(OrderPlan.major, OrderPlan.semester_no).all()
    data = []
    for r in rows:
        tb = db.session.get(Textbook, r.textbook_id)
        data.append(['专业课' if r.major else '文化课', r.major or '', r.semester_no or 1, tb.name if tb else '',
                     course_name(r.course_id) if r.course_id else '',
                     class_name(r.class_id) if r.class_id else '全校/按课程',
                     r.quantity, round(r.unit_price or 0, 2), round((r.quantity or 0) * (r.unit_price or 0), 2),
                     {'draft': '草稿', 'approved': '已审核', 'arrived': '已到货'}.get(r.status, r.status),
                     r.remark or ''])
    bio = _export_workbook([('订书计划', ['类别', '专业', '学期', '教材', '适用课程', '征订范围',
                                        '数量', '单价(元)', '金额(元)', '状态', '备注'], data)])
    fname = '订书计划%s.xlsx' % ('_%s' % major if major else '')
    return send_file(bio, as_attachment=True, download_name=fname,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/books/stats')
@login_required
def books_stats():
    """教材费用/发放统计"""
    sid = get_current_semester_id()
    issues = sem_filter(BookIssue.query).all()
    textbooks = sem_filter(Textbook.query).all()
    # 按教材汇总
    per_book = {}
    total_cost = 0.0
    total_qty = 0
    for i in issues:
        tb = db.session.get(Textbook, i.textbook_id)
        price = tb.price if tb else 0
        cost = i.quantity * price
        total_cost += cost
        total_qty += i.quantity
        key = i.textbook_id
        if key not in per_book:
            per_book[key] = {'name': tb.name if tb else f'#{key}', 'qty': 0, 'cost': 0.0,
                             'class_qty': 0, 'teacher_qty': 0}
        per_book[key]['qty'] += i.quantity
        per_book[key]['cost'] += cost
        if i.issue_type == 'class':
            per_book[key]['class_qty'] += i.quantity
        else:
            per_book[key]['teacher_qty'] += i.quantity
    # 按班级汇总
    per_class = {}
    for i in issues:
        if i.issue_type != 'class' or not i.class_id:
            continue
        tb = db.session.get(Textbook, i.textbook_id)
        price = tb.price if tb else 0
        key = i.class_id
        if key not in per_class:
            per_class[key] = {'name': class_name(key), 'cost': 0.0, 'qty': 0}
        per_class[key]['cost'] += i.quantity * price
        per_class[key]['qty'] += i.quantity
    book_rows = [{'name': v['name'], 'qty': v['qty'], 'class_qty': v['class_qty'],
                  'teacher_qty': v['teacher_qty'], 'cost': round(v['cost'], 2)}
                 for v in per_book.values()]
    book_rows.sort(key=lambda x: -x['cost'])
    class_rows = [{'name': v['name'], 'qty': v['qty'], 'cost': round(v['cost'], 2)}
                  for v in per_class.values()]
    class_rows.sort(key=lambda x: -x['cost'])
    return render_template('books_stats.html', book_rows=book_rows, class_rows=class_rows,
                           total_qty=total_qty, total_cost=round(total_cost, 2),
                           teacher_qty=sum(1 for i in issues if i.issue_type == 'teacher'),
                           textbook_count=len(textbooks))

@app.route('/books/stats/export')
@login_required
def books_stats_export():
    """教材发放统计导出 Excel"""
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, PatternFill
    wb = Workbook()
    ws = wb.active
    ws.title = '教材发放统计'
    school = get_setting('school_name', '榆中县职业技术学校')
    sem = get_semester()
    ws.append([f'{school} 教材发放统计表'])
    ws.append([f'学期：{sem.name if sem else ""}    导出时间：{datetime.now().strftime("%Y-%m-%d %H:%M")}'])
    ws.append([])
    ws.append(['教材名称', '发放总数', '班级发放', '教师教本', '金额(元)'])
    issues = sem_filter(BookIssue.query).all()
    per_book = {}
    total_cost = 0.0
    total_qty = 0
    for i in issues:
        tb = db.session.get(Textbook, i.textbook_id)
        price = tb.price if tb else 0
        cost = i.quantity * price
        total_cost += cost
        total_qty += i.quantity
        k = i.textbook_id
        d = per_book.setdefault(k, {'name': tb.name if tb else '', 'qty': 0, 'cq': 0, 'tq': 0, 'cost': 0.0})
        d['qty'] += i.quantity
        d['cost'] += cost
        if i.issue_type == 'class':
            d['cq'] += i.quantity
        else:
            d['tq'] += i.quantity
    for v in sorted(per_book.values(), key=lambda x: -x['cost']):
        ws.append([v['name'], v['qty'], v['cq'], v['tq'], round(v['cost'], 2)])
    ws.append(['合计', total_qty, '', '', round(total_cost, 2)])
    _apply_uniform_style(ws, header_row=4)
    for c in ws[ws.max_row]:
        c.font = Font(name='宋体', size=11, bold=True)
    ws.column_dimensions['A'].width = 40
    for col in 'BCDE':
        ws.column_dimensions[col].width = 14
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=f'教材发放统计_{datetime.now().strftime("%Y%m%d")}.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# ══════════════════════════════════════════════
# 排课系统：教学任务 + 自动排课 + 手动调整 + 冲突检查
# ══════════════════════════════════════════════

def _slot_conflict(sid, weekday, period, week_type, teacher_id, class_ids, exclude_id=None, exclude_task_id=None):
    """检查教师/班级在槽位上的冲突（教室单独查）。True=有冲突。
    合班课同 task 的多个 cell 视为同一节课，互不冲突。"""
    cells = ScheduleCell.query.filter_by(semester_id=sid, weekday=weekday, period=period).all()
    for c in cells:
        if exclude_id and c.id == exclude_id:
            continue
        if exclude_task_id and c.task_id and c.task_id == exclude_task_id:
            continue
        if not week_type_conflict(week_type, c.week_type):
            continue
        if c.teacher_id == teacher_id:
            return True
        if c.class_id in class_ids:
            return True
    return False


def _room_busy_set(sid, weekday, period, week_type, exclude_id=None, exclude_task_id=None):
    busy = set()
    for c in ScheduleCell.query.filter_by(semester_id=sid, weekday=weekday, period=period).all():
        if exclude_id and c.id == exclude_id:
            continue
        if exclude_task_id and c.task_id and c.task_id == exclude_task_id:
            continue
        if week_type_conflict(week_type, c.week_type) and c.classroom_id:
            busy.add(c.classroom_id)
    return busy


def pick_classroom(sid, weekday, period, week_type, prefer_id=None, exclude_id=None, exclude_task_id=None):
    """挑一个空闲教室；prefer_id 指定时不可用则返回 None（不强行占用）"""
    busy = _room_busy_set(sid, weekday, period, week_type, exclude_id, exclude_task_id)
    if prefer_id:
        return prefer_id if prefer_id not in busy else None
    rooms = Classroom.query.filter_by(semester_id=sid).order_by(Classroom.id).all()
    for r in rooms:
        if r.id not in busy:
            return r.id
    return None


def build_class_grid(sid, cid):
    """构建班级课表网格 grid[period][weekday]"""
    periods = period_list()
    wds = weekday_list()
    grid = [[None for _ in wds] for _ in periods]
    cells = ScheduleCell.query.filter_by(semester_id=sid, class_id=cid).all()
    for c in cells:
        if c.period - 1 < len(periods) and c.weekday - 1 < len(wds):
            grid[c.period - 1][c.weekday - 1] = c
    return grid, periods, wds


def build_teacher_grid(sid, tid):
    periods = period_list()
    wds = weekday_list()
    grid = [[None for _ in wds] for _ in periods]
    cells = ScheduleCell.query.filter_by(semester_id=sid, teacher_id=tid).all()
    for c in cells:
        if c.period - 1 < len(periods) and c.weekday - 1 < len(wds):
            grid[c.period - 1][c.weekday - 1] = c
    return grid, periods, wds


def build_room_grid(sid, rid):
    """教室/实训室课表：只显示分配了该教室的课"""
    periods = period_list()
    wds = weekday_list()
    grid = [[None for _ in wds] for _ in periods]
    cells = ScheduleCell.query.filter_by(semester_id=sid, classroom_id=rid).all()
    for c in cells:
        if c.period - 1 < len(periods) and c.weekday - 1 < len(wds):
            grid[c.period - 1][c.weekday - 1] = c
    return grid, periods, wds


@app.route('/tasks')
@login_required
def tasks_page():
    rows = sem_filter(TeachingTask.query).all()
    classes = sem_filter(ClassInfo.query).order_by(ClassInfo.name).all()
    courses = sem_filter(Course.query).order_by(Course.name).all()
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    classrooms = sem_filter(Classroom.query).order_by(Classroom.name).all()
    return render_template('tasks.html', rows=rows, classes=classes, courses=courses,
                           teachers=teachers, classrooms=classrooms)


@app.route('/tasks/add', methods=['POST'])
@admin_required
def tasks_add():
    course_id = request.form.get('course_id', '').strip()
    teacher_id = request.form.get('teacher_id', '').strip()
    class_ids = request.form.getlist('class_ids')
    if not course_id.isdigit() or not teacher_id.isdigit() or not class_ids:
        flash('请选择班级、课程、教师')
        return redirect(request.referrer or url_for('tasks_page'))
    try:
        weekly_hours = int(request.form.get('weekly_hours', 2) or 2)
    except Exception:
        weekly_hours = 2
    if weekly_hours <= 0:
        weekly_hours = 1
    t = TeachingTask(semester_id=get_current_semester_id(),
                     class_ids=json.dumps([int(x) for x in class_ids]),
                     course_id=int(course_id), teacher_id=int(teacher_id),
                     weekly_hours=weekly_hours,
                     classroom_id=int(request.form.get('classroom_id') or 0) or None,
                     week_type=request.form.get('week_type', 'every'),
                     remark=request.form.get('remark', '').strip())
    db.session.add(t)
    db.session.commit()
    flash('教学任务已添加')
    return redirect(url_for('tasks_page'))


@app.route('/tasks/<int:tid>/edit', methods=['POST'])
@admin_required
def tasks_edit(tid):
    t = db.session.get(TeachingTask, tid)
    if not t:
        flash('任务不存在')
        return redirect(url_for('tasks_page'))
    class_ids = request.form.getlist('class_ids')
    if not class_ids:
        flash('请至少选择一个班级')
        return redirect(url_for('tasks_page'))
    t.class_ids = json.dumps([int(x) for x in class_ids])
    t.course_id = int(request.form.get('course_id') or 0) or t.course_id
    t.teacher_id = int(request.form.get('teacher_id') or 0) or t.teacher_id
    try:
        t.weekly_hours = max(1, int(request.form.get('weekly_hours', 2) or 2))
    except Exception:
        pass
    t.classroom_id = int(request.form.get('classroom_id') or 0) or None
    t.week_type = request.form.get('week_type', 'every')
    t.remark = request.form.get('remark', '').strip()
    db.session.commit()
    flash('教学任务已更新（原课表格子保留，如需重排请重新自动排课）')
    return redirect(url_for('tasks_page'))


@app.route('/tasks/<int:tid>/delete', methods=['POST'])
@admin_required
def tasks_delete(tid):
    t = db.session.get(TeachingTask, tid)
    if not t:
        flash('任务不存在')
        return redirect(url_for('tasks_page'))
    ScheduleCell.query.filter_by(task_id=tid).delete()
    db.session.delete(t)
    db.session.commit()
    flash('教学任务已删除（课表格子同步清除）')
    return redirect(url_for('tasks_page'))


@app.route('/schedule')
@login_required
def schedule_page():
    sid = get_current_semester_id()
    classes = sem_filter(ClassInfo.query).order_by(ClassInfo.name).all()
    cid = request.args.get('class_id', type=int) or (classes[0].id if classes else None)
    grid, periods, wds = ([], [], [])
    if cid:
        grid, periods, wds = build_class_grid(sid, cid)
    courses = sem_filter(Course.query).order_by(Course.name).all()
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    classrooms = sem_filter(Classroom.query).order_by(Classroom.name).all()
    return render_template('schedule.html', classes=classes, cid=cid, grid=grid,
                           periods=periods, wds=wds, weekday_label=weekday_label,
                           courses=courses, teachers=teachers, classrooms=classrooms)


@app.route('/schedule/teacher')
@login_required
def schedule_teacher():
    sid = get_current_semester_id()
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    # 按任教科目排序（与教师管理一致）
    teachers = sorted(teachers, key=lambda t: (_teacher_subject_rank(sid, t.id), t.name))
    tid = request.args.get('teacher_id', type=int) or (teachers[0].id if teachers else None)
    grid, periods, wds = ([], [], [])
    if tid:
        grid, periods, wds = build_teacher_grid(sid, tid)
    courses = sem_filter(Course.query).order_by(Course.name).all()
    classrooms = sem_filter(Classroom.query).order_by(Classroom.name).all()
    return render_template('schedule_teacher.html', teachers=teachers, tid=tid, grid=grid,
                           periods=periods, wds=wds, weekday_label=weekday_label,
                           courses=courses, classrooms=classrooms)


@app.route('/schedule/room')
@login_required
def schedule_room():
    """教室/实训室课表"""
    sid = get_current_semester_id()
    rooms = sem_filter(Classroom.query).order_by(Classroom.name).all()
    rid = request.args.get('room_id', type=int) or (rooms[0].id if rooms else None)
    grid, periods, wds = ([], [], [])
    if rid:
        grid, periods, wds = build_room_grid(sid, rid)
    courses = sem_filter(Course.query).order_by(Course.name).all()
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    classrooms = sem_filter(Classroom.query).order_by(Classroom.name).all()
    return render_template('schedule_room.html', rooms=rooms, rid=rid, grid=grid,
                           periods=periods, wds=wds, weekday_label=weekday_label,
                           courses=courses, teachers=teachers, classrooms=classrooms)


@app.route('/schedule/batch_save', methods=['POST'])
@admin_required
def schedule_batch_save():
    """批量保存课表格子教师修改：changes=[{cell_id, teacher_id}...]
    teacher_id 为 0/空 表示删除该格子"""
    sid = get_current_semester_id()
    try:
        data = request.get_json(silent=True) or {}
        changes = data.get('changes') or []
    except Exception:
        changes = []
    saved = 0
    for ch in changes:
        cid = ch.get('cell_id')
        tid = ch.get('teacher_id')
        if not cid:
            continue
        try:
            cid = int(cid)
        except Exception:
            continue
        cell = db.session.get(ScheduleCell, cid)
        if not cell or cell.semester_id != sid:
            continue
        if tid is None or tid == '' or int(tid or 0) <= 0:
            db.session.delete(cell)
            saved += 1
            continue
        try:
            tid = int(tid)
        except Exception:
            continue
        cell.teacher_id = tid
        saved += 1
    db.session.commit()
    return jsonify({'ok': True, 'saved': saved})


@app.route('/schedule/clear', methods=['POST'])
@admin_required
def schedule_clear():
    ScheduleCell.query.filter_by(semester_id=get_current_semester_id()).delete()
    db.session.commit()
    flash('课表已清空')
    return redirect(url_for('schedule_page'))


@app.route('/schedule/cell/update', methods=['POST'])
@admin_required
def schedule_cell_update():
    """更新单个课表格子：update(改课程/教师/教室/周类型) / move(移动槽位) / delete"""
    cell = db.session.get(ScheduleCell, int(request.form.get('cell_id', 0) or 0))
    if not cell:
        return jsonify({'ok': False, 'error': '格子不存在'})
    action = request.form.get('action', 'update')
    sid = get_current_semester_id()
    if action == 'delete':
        db.session.delete(cell)
        db.session.commit()
        return jsonify({'ok': True, 'msg': '已删除该节课'})
    class_ids = [cell.class_id]
    wt = request.form.get('week_type', cell.week_type) or 'every'
    if wt not in ('every', 'odd', 'even'):
        wt = 'every'
    if action == 'move':
        try:
            wd = int(request.form.get('weekday', 0))
            pd = int(request.form.get('period', 0))
        except Exception:
            return jsonify({'ok': False, 'error': '槽位参数错误'})
        if wd not in weekday_list() or pd not in period_list():
            return jsonify({'ok': False, 'error': '槽位超出范围'})
        if _slot_conflict(sid, wd, pd, wt, cell.teacher_id, class_ids,
                          exclude_id=cell.id, exclude_task_id=cell.task_id):
            return jsonify({'ok': False, 'error': '冲突：该时段教师或班级已有课'})
        room = request.form.get('classroom_id', '').strip()
        if room and room.isdigit():
            rid = int(room)
            if rid in _room_busy_set(sid, wd, pd, wt, exclude_id=cell.id, exclude_task_id=cell.task_id):
                return jsonify({'ok': False, 'error': '冲突：该教室此时间段已被占用'})
            cell.classroom_id = rid
        elif room == '':
            cell.classroom_id = None
        cell.weekday, cell.period, cell.week_type = wd, pd, wt
        db.session.commit()
        return jsonify({'ok': True, 'msg': '已移动到' + weekday_label(wd) + '第' + str(pd) + '节'})
    # update：改课程/教师/教室/周类型
    course_id = request.form.get('course_id', '').strip()
    teacher_id = request.form.get('teacher_id', '').strip()
    if course_id.isdigit():
        cell.course_id = int(course_id)
    if teacher_id.isdigit():
        ntid = int(teacher_id)
        if _slot_conflict(sid, cell.weekday, cell.period, wt, ntid, class_ids,
                          exclude_id=cell.id, exclude_task_id=cell.task_id):
            return jsonify({'ok': False, 'error': '冲突：该教师此时段已有课'})
        cell.teacher_id = ntid
    room = request.form.get('classroom_id', '').strip()
    if room.isdigit():
        rid = int(room)
        if rid in _room_busy_set(sid, cell.weekday, cell.period, wt, exclude_id=cell.id, exclude_task_id=cell.task_id):
            return jsonify({'ok': False, 'error': '冲突：该教室此时间段已被占用'})
        cell.classroom_id = rid
    elif room == '':
        cell.classroom_id = None
    cell.week_type = wt
    db.session.commit()
    return jsonify({'ok': True, 'msg': '已更新'})

# ══════════════════════════════════════════════
# 调课系统：请假申请 → 审批 → 看课教师补助
# ══════════════════════════════════════════════

@app.route('/leaves')
@login_required
def leaves_page():
    q = sem_filter(LeaveRequest.query)
    m = request.args.get('month', '').strip()
    if not m:
        # 默认显示当前日期所在的月
        m = date.today().strftime('%Y-%m')
    if re.match(r'^\d{4}-\d{2}$', m):
        q = q.filter(LeaveRequest.leave_date >= m + '-01') \
            .filter(LeaveRequest.leave_date <= (date(int(m[:4]), int(m[5:7]), 28) + timedelta(days=4)).replace(day=1) - timedelta(days=1))
    rows = q.order_by(LeaveRequest.leave_date.desc()).all()
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    watch_unit = get_setting_float('watch_unit_price', 0)
    periods_per_day = get_setting_int('periods_per_day', 8)
    # 上月/下月（月切换导航用）
    try:
        yy, mm = int(m[:4]), int(m[5:7])
    except Exception:
        yy, mm = date.today().year, date.today().month
    first = date(yy, mm, 1)
    prev_month = (first - timedelta(days=1)).strftime('%Y-%m')
    nxt_month = (date(yy, mm, 28) + timedelta(days=4)).replace(day=1).strftime('%Y-%m')
    return render_template('leaves.html', rows=rows, teachers=teachers,
                           period_list=period_list, watch_unit=watch_unit,
                           periods_per_day=periods_per_day, cur_month=m,
                           prev_month=prev_month, nxt_month=nxt_month)


@app.route('/leaves/add', methods=['POST'])
@admin_required
def leaves_add():
    """添加调课记录：请假教师 + 日期 + 节次 + 调给谁（顶课教师），免审批，自动算补助"""
    teacher_id = request.form.get('teacher_id', '').strip()
    leave_date = request.form.get('leave_date', '').strip()
    periods = request.form.getlist('periods')
    if not teacher_id.isdigit() or not leave_date:
        flash('请选择教师和调课日期')
        return redirect(request.referrer or url_for('leaves_page'))
    if not periods:
        flash('请至少选择一个节次')
        return redirect(request.referrer or url_for('leaves_page'))
    try:
        ld = datetime.strptime(leave_date, '%Y-%m-%d').date()
    except Exception:
        flash('日期格式错误')
        return redirect(request.referrer or url_for('leaves_page'))
    # 节次范围 + 去重校验
    max_p = get_setting_int('periods_per_day', 8)
    try:
        period_ints = sorted({int(p) for p in periods})
    except Exception:
        flash('节次格式错误')
        return redirect(request.referrer or url_for('leaves_page'))
    if not period_ints or min(period_ints) < 1 or max(period_ints) > max_p:
        flash(f'节次必须在 1 ~ {max_p} 之间')
        return redirect(request.referrer or url_for('leaves_page'))
    # 调给谁（顶课教师）
    watch_tid = request.form.get('watch_teacher_id', '').strip()
    watch_tid = int(watch_tid) if watch_tid.isdigit() else 0
    leave_type = '调课'  # 统一按调课，不再区分换课/调课
    unit = get_setting_float('watch_unit_price', 0)
    lv = LeaveRequest(semester_id=get_current_semester_id(), teacher_id=int(teacher_id),
                      leave_date=ld, periods=json.dumps(period_ints),
                      reason=request.form.get('reason', '').strip(),
                      leave_type=leave_type,
                      status='approved', watch_teacher_id=watch_tid or None)
    if watch_tid:
        lv.watch_amount = round(len(period_ints) * unit, 2)
        lv.watch_note = '%d节 × %s元/节' % (len(period_ints), unit)
    db.session.add(lv)
    db.session.commit()
    flash('调课已登记' + ('，%s 看课补助 %s 元' % (teacher_name(watch_tid), lv.watch_amount) if watch_tid else '（未指定顶课教师）'))
    return redirect(url_for('leaves_page'))


@app.route('/leaves/<int:lid>/edit', methods=['POST'])
@admin_required
def leaves_edit(lid):
    """编辑调课记录：改日期/节次/顶课教师，自动重算补助"""
    lv = db.session.get(LeaveRequest, lid)
    if not lv:
        flash('记录不存在')
        return redirect(url_for('leaves_page'))
    teacher_id = request.form.get('teacher_id', '').strip()
    leave_date = request.form.get('leave_date', '').strip()
    periods = request.form.getlist('periods')
    if not teacher_id.isdigit() or not leave_date or not periods:
        flash('请填写教师、日期和节次')
        return redirect(request.referrer or url_for('leaves_page'))
    try:
        ld = datetime.strptime(leave_date, '%Y-%m-%d').date()
        period_ints = sorted({int(p) for p in periods})
    except Exception:
        flash('参数格式错误')
        return redirect(request.referrer or url_for('leaves_page'))
    max_p = get_setting_int('periods_per_day', 8)
    if not period_ints or min(period_ints) < 1 or max(period_ints) > max_p:
        flash(f'节次必须在 1 ~ {max_p} 之间')
        return redirect(request.referrer or url_for('leaves_page'))
    watch_tid = request.form.get('watch_teacher_id', '').strip()
    watch_tid = int(watch_tid) if watch_tid.isdigit() else 0
    leave_type = '调课'  # 统一按调课
    lv.teacher_id = int(teacher_id)
    lv.leave_date = ld
    lv.periods = json.dumps(period_ints)
    lv.reason = request.form.get('reason', '').strip()
    lv.watch_teacher_id = watch_tid or None
    unit = get_setting_float('watch_unit_price', 0)
    if watch_tid:
        lv.watch_amount = round(len(period_ints) * unit, 2)
        lv.watch_note = '%d节 × %s元/节' % (len(period_ints), unit)
    else:
        lv.watch_amount = 0
        lv.watch_note = ''
    db.session.commit()
    flash('调课记录已更新')
    return redirect(url_for('leaves_page'))

@app.route('/leaves/<int:lid>/watch', methods=['POST'])
@admin_required
def leaves_watch(lid):
    """已通过后修改/确认看课教师"""
    lv = db.session.get(LeaveRequest, lid)
    if not lv:
        return jsonify({'ok': False, 'error': '申请不存在'})
    if lv.status != 'approved':
        return jsonify({'ok': False, 'error': '请先审批通过'})
    watch_tid = request.form.get('watch_teacher_id', '').strip()
    if not watch_tid.isdigit():
        return jsonify({'ok': False, 'error': '请选择看课教师'})
    lv.watch_teacher_id = int(watch_tid)
    unit = get_setting_float('watch_unit_price', 0)
    lv.watch_amount = round(len(lv.period_list()) * unit, 2)
    lv.watch_note = f'{len(lv.period_list())}节 × {unit}元/节'
    db.session.commit()
    return jsonify({'ok': True, 'msg': '看课教师已确认，补助 ' + str(lv.watch_amount) + ' 元'})

@app.route('/leaves/<int:lid>/delete', methods=['POST'])
@admin_required
def leaves_delete(lid):
    lv = db.session.get(LeaveRequest, lid)
    if not lv:
        flash('申请不存在')
        return redirect(url_for('leaves_page'))
    db.session.delete(lv)
    db.session.commit()
    flash('请假记录已删除')
    return redirect(url_for('leaves_page'))


@app.route('/leaves/stats')
@login_required
def leaves_stats():
    """调课补助统计（统一按调课，顶课教师汇总）"""
    sid = get_current_semester_id()
    rows = LeaveRequest.query.filter_by(semester_id=sid, status='approved') \
        .filter(LeaveRequest.watch_teacher_id.isnot(None)).all()
    by_teacher = {}
    total_amount = 0.0
    for r in rows:
        tid = r.watch_teacher_id
        d = by_teacher.setdefault(tid, {'name': teacher_name(tid), 'count': 0,
                                        'periods': 0, 'amount': 0.0})
        d['count'] += 1
        d['periods'] += len(r.period_list())
        d['amount'] += r.watch_amount or 0
        total_amount += r.watch_amount or 0
    items = sorted(by_teacher.values(), key=lambda x: -x['amount'])
    return render_template('leaves_stats.html', items=items, rows=rows,
                           total=round(total_amount, 2),
                           watch_unit=get_setting_float('watch_unit_price', 0))

# ══════════════════════════════════════════════
# 超课时统计：职务标准课时 + 学科系数 + 节假日 + 自动统计
# ══════════════════════════════════════════════

@app.route('/standards')
@login_required
def standards_page():
    positions = PositionStandard.query.order_by(PositionStandard.weekly_std_hours.desc()).all()
    coefs = CourseCoefficient.query.order_by(CourseCoefficient.id).all()
    return render_template('standards.html', positions=positions, coefs=coefs)


@app.route('/standards/position/add', methods=['POST'])
@admin_required
def standards_position_add():
    position = request.form.get('position', '').strip()
    if not position:
        flash('职务名称不能为空')
        return redirect(url_for('standards_page'))
    if PositionStandard.query.filter_by(position=position).first():
        flash('该职务已存在')
        return redirect(url_for('standards_page'))
    try:
        hours = float(request.form.get('weekly_std_hours', 12) or 12)
    except Exception:
        hours = 12
    db.session.add(PositionStandard(position=position, weekly_std_hours=hours,
                                    note=request.form.get('note', '').strip()))
    db.session.commit()
    flash('职务标准课时已添加')
    return redirect(url_for('standards_page'))


@app.route('/standards/position/<int:pid>/edit', methods=['POST'])
@admin_required
def standards_position_edit(pid):
    p = db.session.get(PositionStandard, pid)
    if not p:
        flash('记录不存在')
        return redirect(url_for('standards_page'))
    try:
        p.weekly_std_hours = float(request.form.get('weekly_std_hours', p.weekly_std_hours))
    except Exception:
        pass
    p.note = request.form.get('note', '').strip()
    db.session.commit()
    flash('标准课时已更新')
    return redirect(url_for('standards_page'))


@app.route('/standards/position/<int:pid>/delete', methods=['POST'])
@admin_required
def standards_position_delete(pid):
    p = db.session.get(PositionStandard, pid)
    if not p:
        flash('记录不存在')
        return redirect(url_for('standards_page'))
    db.session.delete(p)
    db.session.commit()
    flash('已删除')
    return redirect(url_for('standards_page'))


@app.route('/standards/coef/add', methods=['POST'])
@admin_required
def standards_coef_add():
    category = request.form.get('category', '').strip()
    if not category:
        flash('类别名称不能为空')
        return redirect(url_for('standards_page'))
    if CourseCoefficient.query.filter_by(category=category).first():
        flash('该类别已存在')
        return redirect(url_for('standards_page'))
    try:
        coef = float(request.form.get('coefficient', 1.0) or 1.0)
    except Exception:
        coef = 1.0
    db.session.add(CourseCoefficient(category=category, coefficient=coef,
                                     note=request.form.get('note', '').strip()))
    db.session.commit()
    flash('学科系数已添加')
    return redirect(url_for('standards_page'))


@app.route('/standards/coef/<int:cid>/edit', methods=['POST'])
@admin_required
def standards_coef_edit(cid):
    c = db.session.get(CourseCoefficient, cid)
    if not c:
        flash('记录不存在')
        return redirect(url_for('standards_page'))
    try:
        c.coefficient = float(request.form.get('coefficient', c.coefficient))
    except Exception:
        pass
    c.note = request.form.get('note', '').strip()
    db.session.commit()
    flash('系数已更新')
    return redirect(url_for('standards_page'))


@app.route('/standards/coef/<int:cid>/delete', methods=['POST'])
@admin_required
def standards_coef_delete(cid):
    c = db.session.get(CourseCoefficient, cid)
    if not c:
        flash('记录不存在')
        return redirect(url_for('standards_page'))
    db.session.delete(c)
    db.session.commit()
    flash('已删除')
    return redirect(url_for('standards_page'))


@app.route('/holidays')
@login_required
def holidays_page():
    rows = sem_filter(Holiday.query).order_by(Holiday.holiday_date).all()
    return render_template('holidays.html', rows=rows)


@app.route('/holidays/add', methods=['POST'])
@admin_required
def holidays_add():
    hd = request.form.get('holiday_date', '').strip()
    name = request.form.get('name', '').strip() or '放假'
    try:
        d = datetime.strptime(hd, '%Y-%m-%d').date()
    except Exception:
        flash('日期格式错误')
        return redirect(request.referrer or url_for('holidays_page'))
    if Holiday.query.filter_by(semester_id=get_current_semester_id(), holiday_date=d).first():
        flash('该日期已在停课名单中')
        return redirect(request.referrer or url_for('holidays_page'))
    db.session.add(Holiday(semester_id=get_current_semester_id(), holiday_date=d,
                           name=name, remark=request.form.get('remark', '').strip()))
    db.session.commit()
    flash('停课日已添加')
    return redirect(url_for('holidays_page'))


@app.route('/holidays/<int:hid>/delete', methods=['POST'])
@admin_required
def holidays_delete(hid):
    h = db.session.get(Holiday, hid)
    if not h:
        flash('记录不存在')
        return redirect(url_for('holidays_page'))
    db.session.delete(h)
    db.session.commit()
    flash('已删除')
    return redirect(url_for('holidays_page'))


def coefficient_of_course(course_id):
    """课程类别对应的课时系数，找不到返回 1.0"""
    c = db.session.get(Course, course_id) if course_id else None
    if not c:
        return 1.0
    co = CourseCoefficient.query.filter_by(category=c.category).first()
    return co.coefficient if co and co.coefficient else 1.0


def position_std_hours(position):
    p = PositionStandard.query.filter_by(position=position).first()
    return p.weekly_std_hours if p else 12.0


def _int_if_whole(v):
    """值等于整数时转 int，避免界面出现 15.0 这类小数点（0.5 隔周课等真实小数保留）"""
    try:
        if float(v) == int(v):
            return int(v)
    except (TypeError, ValueError):
        pass
    return v


def workload_rows(sid):
    """超课时统计明细行（无学科系数，上一节算一节，全部整数）"""
    if not sid:
        return [], 0
    sem = db.session.get(Semester, sid) if sid else None
    weeks = sem.effective_weeks() if sem else 0
    teachers = Teacher.query.filter_by(semester_id=sid, is_active=True).order_by(Teacher.name).all()
    rows = []
    for t in teachers:
        cells = ScheduleCell.query.filter_by(semester_id=sid, teacher_id=t.id).all()
        weekly_raw = 0.0
        # 按 (task, 周几, 节次) 去重：合班课同一节课有多个班的 cell，只计一次
        seen = set()
        for c in cells:
            key = ((c.task_id or ('c%d' % c.class_id)), c.weekday, c.period)
            if key in seen:
                continue
            seen.add(key)
            wt = 1.0 if c.week_type == 'every' else 0.5
            weekly_raw += wt
        # 请假扣减：已通过的请假节次（含看课的），直接扣实际课时
        leaves = LeaveRequest.query.filter_by(semester_id=sid, teacher_id=t.id, status='approved').all()
        leave_periods = sum(len(l.period_list()) for l in leaves)
        actual = max(0, round(weekly_raw * weeks) - leave_periods)
        std_weekly = position_std_hours(t.position)
        std_total = round(std_weekly * weeks)
        extra = max(0, actual - std_total)
        amount = extra * int(get_setting_float('extra_hour_unit_price', 0) + 0.5)
        rows.append({'teacher': t, 'weekly_raw': _int_if_whole(round(weekly_raw, 2)),
                     'weekly_coef': _int_if_whole(round(weekly_raw, 2)), 'weeks': weeks,
                     'actual': actual, 'leave_periods': leave_periods,
                     'std_weekly': _int_if_whole(std_weekly), 'std_total': std_total,
                     'extra': extra, 'amount': amount})
    rows.sort(key=lambda r: -r['extra'])
    return rows, weeks


def _month_weeks(sem):
    """学期内每月教学周数（从 start_date 起每 7 天为 1 周，按月归组）"""
    res = []
    if not sem:
        return res
    d = sem.start_date
    m = d.strftime('%Y-%m')
    cnt = 0
    while d <= sem.end_date:
        if d.strftime('%Y-%m') != m:
            res.append((m, cnt))
            m = d.strftime('%Y-%m')
            cnt = 0
        cnt += 1
        d += timedelta(days=7)
    if cnt:
        res.append((m, cnt))
    return res


def _period_weeks(sem):
    """学期内每 4 周一个结算周期：[(period_no, start, end, 有效周数)]
    第 1 周 = 包含学期开始日的那一周（以该周周日为基准）；周期有效周数按自然周计算，
    放假停课也按整周算，恒为整数（完整周期=4，末周期按实际自然周数）"""
    if not sem:
        return []
    res = []
    base = sem.start_date - timedelta(days=(sem.start_date.weekday() + 1) % 7)
    d = sem.start_date
    pno = 1
    p_start = d
    while d <= sem.end_date:
        span = (d - base).days + 1
        if span % 28 == 0 or d == sem.end_date:
            eff = int(((d - p_start).days // 7) + 1)
            res.append((pno, p_start, d, eff))
            pno += 1
            p_start = d + timedelta(days=1)
        d += timedelta(days=1)
    return res


def _current_period_no(sid):
    """当前日期所在的 4 周周期号（第 1 周=学期开始日所在周）"""
    sem = db.session.get(Semester, sid) if sid else None
    if not sem:
        return 1
    today = date.today()
    if not (sem.start_date <= today <= sem.end_date):
        return 1
    sem_sun = sem.start_date - timedelta(days=(sem.start_date.weekday() + 1) % 7)
    wno = ((today - sem_sun).days // 7) + 1
    return (wno - 1) // 4 + 1


def _teacher_weekly_coef(sid, tid):
    """教师周课时（无系数，上一节算一节），按 (task, 周几, 节次) 去重合班"""
    cells = ScheduleCell.query.filter_by(semester_id=sid, teacher_id=tid).all()
    weekly_raw = 0.0
    seen = set()
    for c in cells:
        key = ((c.task_id or ('c%d' % c.class_id)), c.weekday, c.period)
        if key in seen:
            continue
        seen.add(key)
        wt = 1.0 if c.week_type == 'every' else 0.5
        weekly_raw += wt
    return round(weekly_raw, 2), round(weekly_raw, 2)


def workload_period_rows(sid, pno):
    """按 4 周周期统计超课时：每位教师 周期实际/标准/超课时/金额"""
    if not sid:
        return [], []
    sem = db.session.get(Semester, sid) if sid else None
    periods = _period_weeks(sem)
    target = next((p for p in periods if p[0] == pno), None)
    if not target:
        return [], periods
    _, p_start, p_end, eff_weeks = target
    unit = get_setting_float('extra_hour_unit_price', 0)
    teachers = Teacher.query.filter_by(semester_id=sid, is_active=True).order_by(Teacher.name).all()
    rows = []
    for t in teachers:
        weekly_raw, weekly_coef = _teacher_weekly_coef(sid, t.id)
        leaves = LeaveRequest.query.filter_by(semester_id=sid, teacher_id=t.id, status='approved') \
            .filter(LeaveRequest.leave_date >= p_start, LeaveRequest.leave_date <= p_end).all()
        leave_periods = sum(len(l.period_list()) for l in leaves)
        actual = max(0, round(weekly_raw * eff_weeks) - leave_periods)
        std_weekly = position_std_hours(t.position)
        std_total = round(std_weekly * eff_weeks)
        extra = max(0, actual - std_total)
        amount = extra * int(get_setting_float('extra_hour_unit_price', 0) + 0.5)
        rows.append({'teacher': t, 'weekly_raw': _int_if_whole(weekly_raw),
                     'weekly_coef': _int_if_whole(weekly_coef), 'weeks': eff_weeks,
                     'actual': actual, 'leave_periods': leave_periods,
                     'std_weekly': _int_if_whole(std_weekly), 'std_total': std_total,
                     'extra': extra, 'amount': amount})
    rows.sort(key=lambda r: -r['extra'])
    return rows, periods


@app.route('/workload')
@login_required
def workload_page():
    sid = get_current_semester_id()
    view = request.args.get('view', 'period')
    unit = get_setting_float('extra_hour_unit_price', 0)
    sem = db.session.get(Semester, sid) if sid else None
    if view == 'period':
        # 4 周周期结算视图（默认当前日期所在周期）
        period_nos = [p[0] for p in _period_weeks(sem)] if sem else []
        p_str = request.args.get('period', '')
        if p_str.isdigit() and int(p_str) in period_nos:
            cur_period = int(p_str)
        else:
            cur_period = _current_period_no(sid)
            if cur_period not in period_nos:
                cur_period = period_nos[-1] if period_nos else 1
        rows, periods = workload_period_rows(sid, cur_period)
        p_weeks = [p for p in periods if p[0] == cur_period]
        total_extra = round(sum(r['extra'] for r in rows), 2)
        total_amount = round(sum(r['amount'] for r in rows), 2)
        return render_template('workload.html', rows=rows, weeks=0, view='period',
                               total_extra=total_extra, total_amount=total_amount, unit=unit,
                               period_nos=period_nos, cur_period=cur_period, p_weeks=p_weeks,
                               classes=[], cid=None, grid={}, teachers=[], p_rows=[])
    # 按周（整学期）视图
    rows, weeks = workload_rows(sid)
    total_extra = sum(r['extra'] for r in rows)
    total_amount = round(sum(r['amount'] for r in rows), 2)
    return render_template('workload.html', rows=rows, weeks=weeks, view='week',
                           total_extra=round(total_extra, 2), total_amount=total_amount, unit=unit,
                           period_nos=[], cur_period=1, p_weeks=[],
                           classes=[], cid=None, grid={}, teachers=[], p_rows=[])


@app.route('/workload/export')
@login_required
def workload_export():
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, PatternFill
    sid = get_current_semester_id()
    rows, weeks = workload_rows(sid)
    sem = get_semester()
    wb = Workbook()
    ws = wb.active
    ws.title = '超课时统计'
    school = get_setting('school_name', '')
    ws.append([f'{school} 超课时统计表'])
    ws.append([f'学期：{sem.name if sem else ""}    有效教学周数：{weeks}    超课时单价：{get_setting_float("extra_hour_unit_price", 0)} 元/节'])
    ws.append([])
    ws.append(['教师', '职务', '学科类别', '周课时(课表)', '系数折算周课时', '有效周数',
               '学期实际课时', '请假扣减', '职务周标准', '标准课时', '超课时', '金额(元)'])
    for r in rows:
        ws.append([r['teacher'].name, r['teacher'].position, r['teacher'].subject_category,
                   r['weekly_raw'], r['weekly_coef'], r['weeks'], r['actual'],
                   r['leave_periods'], r['std_weekly'], r['std_total'], r['extra'], r['amount']])
    ws.append(['合计', '', '', '', '', '', '', '', '', '',
               round(sum(r['extra'] for r in rows), 2), round(sum(r['amount'] for r in rows), 2)])
    _apply_uniform_style(ws, header_row=4)
    for c in ws[ws.max_row]:
        c.font = Font(name='宋体', size=11, bold=True)
    for col, w in zip('ABCDEFGHIJKL', [10, 12, 10, 12, 13, 9, 12, 10, 10, 10, 9, 10]):
        ws.column_dimensions[col].width = w
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=f'超课时统计_{datetime.now().strftime("%Y%m%d")}.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# ══════════════════════════════════════════════
# 夜自习管理
# ══════════════════════════════════════════════

def _class_room_sort_key(cid):
    """按本班教室门牌号排序（安排表顺序）"""
    c = db.session.get(ClassInfo, cid)
    if c and c.classroom_id:
        r = db.session.get(Classroom, c.classroom_id)
        m = re.search(r'\d+', r.room_no or '') if r else None
        return int(m.group()) if m else 9999
    return 9999


@app.route('/night')
@login_required
def night_page():
    """夜自习周视图：行=班级(教室)，列=周日~周四，格子=教师（可直接改）"""
    sid = get_current_semester_id()
    start_str = request.args.get('start', '')
    if start_str in ('today', '本周'):
        # 明确"本周"：今天所在周（不跳到最近记录周）
        today = date.today()
        start = today - timedelta(days=(today.weekday() + 1) % 7)
    elif start_str:
        try:
            start = datetime.strptime(start_str, '%Y-%m-%d').date()
        except Exception:
            start = None
    else:
        start = None
    if start is None:
        # 默认显示当前日期所在的周
        today = date.today()
        start = today - timedelta(days=(today.weekday() + 1) % 7)  # 本周周日
    else:
        # 显式指定也对齐到该周周日（防止错位）
        start = start - timedelta(days=(start.weekday() + 1) % 7)
    days = [start + timedelta(days=i) for i in range(5)]  # 星期日~星期四
    rows = NightShift.query.filter_by(semester_id=sid) \
        .filter(NightShift.shift_date.in_(days)).all()
    grid = {}
    for r in rows:
        grid.setdefault(r.class_id, {})[r.shift_date] = r
    class_ids = sorted(grid.keys(), key=_class_room_sort_key)
    classes = sem_filter(ClassInfo.query).order_by(ClassInfo.name).all()
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    sem = db.session.get(Semester, sid) if sid else None
    semester_start = sem.start_date if sem else None
    week_no = ''
    if semester_start:
        # 第 1 周 = 包含学期开始日的那一周（以该周周日为基准），之后每周 +1
        sem_sun = semester_start - timedelta(days=(semester_start.weekday() + 1) % 7)
        week_no = max(1, ((start - sem_sun).days // 7) + 1)
    return render_template('night.html', grid=grid, class_ids=class_ids, days=days,
                           start=start, prev_start=start - timedelta(days=7),
                           next_start=start + timedelta(days=7),
                           classes=classes, teachers=teachers,
                           semester_start=semester_start, week_no=week_no)


@app.route('/night/add', methods=['POST'])
@admin_required
def night_add():
    shift_date = request.form.get('shift_date', '').strip()
    class_id = request.form.get('class_id', '').strip()
    teacher_id = request.form.get('teacher_id', '').strip()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if not shift_date or not class_id.isdigit() or not teacher_id.isdigit():
        if is_ajax:
            return jsonify({'ok': False, 'error': '参数不完整'})
        flash('请选择日期、班级、教师')
        return redirect(request.referrer or url_for('night_page'))
    try:
        d = datetime.strptime(shift_date, '%Y-%m-%d').date()
    except Exception:
        if is_ajax:
            return jsonify({'ok': False, 'error': '日期格式错误'})
        flash('日期格式错误')
        return redirect(request.referrer or url_for('night_page'))
    # 去重：同日期同班级已有记录则更新教师
    exist = NightShift.query.filter_by(semester_id=get_current_semester_id(),
                                       shift_date=d, class_id=int(class_id)).first()
    if exist:
        exist.teacher_id = int(teacher_id)
        if is_ajax:
            db.session.commit()
            return jsonify({'ok': True, 'msg': '已更新', 'id': exist.id})
        flash('该班级该日已有排班，已更新教师')
        db.session.commit()
        return redirect(request.referrer or url_for('night_page'))
    new = NightShift(semester_id=get_current_semester_id(), shift_date=d,
                     class_id=int(class_id), teacher_id=int(teacher_id),
                     note=request.form.get('note', '').strip())
    db.session.add(new)
    db.session.commit()
    if is_ajax:
        return jsonify({'ok': True, 'msg': '已添加', 'id': new.id})
    flash('夜自习排班已添加')
    return redirect(request.referrer or url_for('night_page'))


@app.route('/night/<int:nid>/edit', methods=['POST'])
@admin_required
def night_edit(nid):
    """换人/改状态（灵活调整）"""
    n = db.session.get(NightShift, nid)
    if not n:
        return jsonify({'ok': False, 'error': '记录不存在'})
    teacher_id = request.form.get('teacher_id', '').strip()
    if teacher_id.isdigit():
        n.teacher_id = int(teacher_id)
    status = request.form.get('status', '').strip()
    if status in ('scheduled', 'confirmed', 'absent'):
        n.status = status
    n.note = request.form.get('note', n.note or '').strip()
    db.session.commit()
    return jsonify({'ok': True, 'msg': '已更新'})


@app.route('/night/<int:nid>/delete', methods=['POST'])
@admin_required
def night_delete(nid):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    n = db.session.get(NightShift, nid)
    if not n:
        if is_ajax:
            return jsonify({'ok': False, 'error': '记录不存在'})
        flash('记录不存在')
        return redirect(url_for('night_page'))
    db.session.delete(n)
    db.session.commit()
    if is_ajax:
        return jsonify({'ok': True})
    flash('排班已删除')
    return redirect(url_for('night_page'))


def _norm_cname(s):
    """班级名规范化：去全角括号/空格；汽修=汽车、汽车应用=汽车运用（同义叫法）"""
    return (re.sub(r'[（）()]', '', s or '').replace(' ', '').replace('\u3000', '')
            .replace('汽修', '汽车').replace('汽车应用', '汽车运用'))


def _match_class(sid, cname):
    """夜自习安排表班级名 → 系统班级（精确 → 规范化相等 → 去年份前缀相等 → 关键词包含，均规范化比较）"""
    cname = (cname or '').strip()
    if not cname:
        return None
    nc = _norm_cname(cname)

    def year_of(s):
        """班级名前缀年份：'2025供用电焊接班'/'25供用电焊接班' → '2025'，无年份 → ''"""
        m = re.match(r'^20(\d{2})', s or '')
        if m:
            return '20' + m.group(1)
        m = re.match(r'^(\d{2})', s or '')
        return '20' + m.group(1) if m else ''

    def strip_year(s):
        """去掉前缀年份（4 位优先，其次 2 位）：'2025汽车运用班'/'25汽车运用班' → '汽车运用班'"""
        s2 = re.sub(r'^20\d{2}', '', s or '')
        if s2 != s:
            return s2
        return re.sub(r'^\d{2}', '', s or '')

    cand = ClassInfo.query.filter_by(semester_id=sid, name=cname).first()
    if cand:
        return cand
    for c in ClassInfo.query.filter_by(semester_id=sid).all():
        if _norm_cname(c.name) == nc:
            return c
    c2 = re.sub(r'^20(\d{2})', r'\1', nc)
    for c in ClassInfo.query.filter_by(semester_id=sid).all():
        if _norm_cname(c.name) == c2:
            return c
    base = strip_year(nc)
    best = None
    best_len = -1
    y1 = year_of(nc)
    for c in ClassInfo.query.filter_by(semester_id=sid).all():
        cb = strip_year(_norm_cname(c.name))
        if cb and (cb in base or base in cb):
            # 年份一致性：双方都带年份且不同 → 不匹配（2025汽车应用班 ≠ 2024汽车应用班）
            y2 = year_of(_norm_cname(c.name))
            if y1 and y2 and y1 != y2:
                continue
            if len(cb) > best_len:
                best = c
                best_len = len(cb)
    return best


@app.route('/night/import', methods=['POST'])
@admin_required
def night_import():
    """第一步：上传夜自习安排表，保存文件并让用户选择 sheet 页"""
    f = request.files.get('file')
    if not f or not f.filename:
        flash('请选择夜自习安排表文件')
        return redirect(url_for('night_page'))
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ('xlsx', 'xls'):
        flash('仅支持 Excel 文件')
        return redirect(url_for('night_page'))
    path = os.path.join(IMPORT_TMP, 'night_upload_%s.%s' % (session.get('user_id', '0'), ext))
    f.save(path)
    try:
        import openpyxl
        wb = openpyxl.load_workbook(path, data_only=True)
        sheets = wb.sheetnames
    except Exception as e:
        flash('文件解析失败：%s' % e)
        return redirect(url_for('night_page'))
    session['night_upload'] = os.path.basename(path)
    last_sheet = session.get('night_last_sheet', '')
    last_weeks = session.get('night_last_weeks', '')
    return render_template('night_sheet.html', sheets=sheets, filename=f.filename,
                           last_sheet=last_sheet, last_weeks=last_weeks)


@app.route('/night/import/do', methods=['POST'])
@admin_required
def night_import_do():
    """第二步：按选定 sheet 解析导入"""
    sheet_name = request.form.get('sheet', '').strip()
    # 记住本次选择，下次上传自动带出
    session['night_last_sheet'] = sheet_name
    session['night_last_weeks'] = request.form.get('weeks', '1').strip() or '1'
    path = os.path.join(IMPORT_TMP, session.get('night_upload', '') or '')
    if not os.path.exists(path):
        flash('上传文件已失效，请重新上传')
        return redirect(url_for('night_page'))
    start_str = request.form.get('start_date', '').strip()
    try:
        start = datetime.strptime(start_str, '%Y-%m-%d').date() if start_str else date.today()
    except Exception:
        start = date.today()
    # 起始日期自动对齐到所在周的周日（安排表以周日为一周第一天）
    start = start - timedelta(days=(start.weekday() + 1) % 7)
    try:
        weeks = int(request.form.get('weeks', '1') or '1')
    except Exception:
        weeks = 1
    weeks = max(1, min(weeks, 30))
    sid = get_current_semester_id()
    added = skipped = 0
    notes = []
    try:
        import openpyxl
        wb = openpyxl.load_workbook(path, data_only=True)
        if sheet_name not in wb.sheetnames:
            flash('sheet 不存在：%s' % sheet_name)
            return redirect(url_for('night_page'))
        ws = wb[sheet_name]
        rows = list(ws.iter_rows(values_only=True))
        # 定位表头行（含"班级" 和 "星期"）
        header_i = None
        for i, row in enumerate(rows):
            joined = ' '.join(str(v) for v in row if v is not None)
            if '班级' in joined and '星期' in joined:
                header_i = i
                break
        if header_i is None:
            flash('该 sheet 未找到表头行（需包含"班级"与"星期"列）')
            return redirect(url_for('night_page'))
        header = [str(v).strip() if v is not None else '' for v in rows[header_i]]
        col_class = None
        day_cols = []
        for ci, h in enumerate(header):
            if h == '班级':
                col_class = ci
            if h.startswith('星期'):
                day_cols.append(ci)  # 星期日~星期四 均安排自习
        if col_class is None or not day_cols:
            flash('该 sheet 未找到"班级"列或星期列')
            return redirect(url_for('night_page'))
        for row in rows[header_i + 1:]:
            vals = [str(v).strip() if v is not None else '' for v in row]
            cname = vals[col_class] if col_class < len(vals) else ''
            if not cname or '备注' in cname or '教室' in cname:
                continue
            cls = _match_class(sid, cname)
            if not cls:
                # 班级库不存在 → 自动创建班级（年级按年份前缀推断），避免整班数据丢失
                cls = ClassInfo(semester_id=sid, name=cname, grade=_infer_grade(cname))
                db.session.add(cls)
                db.session.flush()
                notes.append('自动创建班级「%s」' % cname)
            for k, dci in enumerate(day_cols):
                tname = vals[dci] if dci < len(vals) else ''
                if not tname:
                    continue
                tc = Teacher.query.filter_by(semester_id=sid, name=tname).first()
                if not tc:
                    tc = Teacher(semester_id=sid, name=tname,
                                 position='专任教师', subject_category='专业课')
                    db.session.add(tc)
                    db.session.flush()
                    notes.append('自动创建教师「%s」' % tname)
                for w in range(weeks):
                    d = start + timedelta(days=7 * w + k)
                    dup = NightShift.query.filter_by(semester_id=sid, shift_date=d,
                                                     class_id=cls.id, teacher_id=tc.id).first()
                    if dup:
                        skipped += 1
                        continue
                    db.session.add(NightShift(semester_id=sid, shift_date=d,
                                              class_id=cls.id, teacher_id=tc.id))
                    added += 1
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash('夜自习安排表解析失败：%s' % e)
        return redirect(url_for('night_page'))
    finally:
        try:
            os.remove(path)
        except Exception:
            pass
        session.pop('night_upload', None)
    msg = '夜自习导入完成：新增 %d 条，跳过 %d 条（起始日 %s，%d 周，sheet「%s」）' % (added, skipped, start, weeks, sheet_name)
    if notes:
        msg += '；' + '；'.join(notes[:6])
    flash(msg)
    return redirect(url_for('night_page'))


@app.route('/night/day_clear', methods=['POST'])
@admin_required
def night_day_clear():
    """整日不上自习：清空某天全部夜自习记录"""
    sid = get_current_semester_id()
    d = request.form.get('date', '').strip()
    try:
        dt = datetime.strptime(d, '%Y-%m-%d').date()
    except Exception:
        return jsonify({'ok': False, 'error': '日期格式错误'})
    n = NightShift.query.filter_by(semester_id=sid, shift_date=dt).delete()
    db.session.commit()
    return jsonify({'ok': True, 'deleted': n})


@app.route('/night/batch_save', methods=['POST'])
@admin_required
def night_batch_save():
    """批量保存夜自习统计修改：changes=[{date, class_id, teacher_id?, status?}...]
    已有记录（日期+班级）则按传入字段更新，无则创建；teacher_id 为空/缺省表示删除该记录；
    status 仅当显式传入（scheduled/confirmed/absent）时更新，不再强制重置为 scheduled"""
    sid = get_current_semester_id()
    try:
        data = request.get_json(silent=True) or {}
        changes = data.get('changes') or []
    except Exception:
        changes = []
    saved = 0
    for ch in changes:
        d = str(ch.get('date', '')).strip()
        cid = ch.get('class_id')
        tid = ch.get('teacher_id')
        status = ch.get('status')
        if not d or not cid:
            continue
        try:
            dt = datetime.strptime(d, '%Y-%m-%d').date()
            cid = int(cid)
        except Exception:
            continue
        if status is not None and status not in ('scheduled', 'confirmed', 'absent'):
            status = None
        tid_empty = tid is None or str(tid).strip() == '' or str(tid).strip() == '0'
        rec = NightShift.query.filter_by(semester_id=sid, shift_date=dt, class_id=cid).first()
        if tid_empty:
            # 清空该格：删除记录
            if rec:
                db.session.delete(rec)
                saved += 1
            continue
        try:
            tid = int(tid or 0)
        except Exception:
            continue
        if rec:
            changed = False
            if 'teacher_id' in ch and rec.teacher_id != tid:
                rec.teacher_id = tid
                changed = True
            if status and rec.status != status:
                rec.status = status
                changed = True
            if changed:
                saved += 1
        else:
            db.session.add(NightShift(semester_id=sid, shift_date=dt, class_id=cid,
                                      teacher_id=tid, status=status or 'scheduled'))
            saved += 1
    db.session.commit()
    return jsonify({'ok': True, 'saved': saved})


@app.route('/night/stats')
@login_required
def night_stats():
    """夜自习统计：按周显示排班表（每天可调整保存）+ 周统计 + 每4周周期补助"""
    sid = get_current_semester_id()
    sem = db.session.get(Semester, sid) if sid else None
    unit = get_setting_float('night_shift_unit_price', 0)
    # 周定位（同排班页：默认最近有数据的周，start 对齐周日）
    start_str = request.args.get('start', '')
    if start_str in ('today', '本周'):
        # 明确"本周"：今天所在周（不跳到最近记录周）
        today = date.today()
        start = today - timedelta(days=(today.weekday() + 1) % 7)
    elif start_str:
        try:
            start = datetime.strptime(start_str, '%Y-%m-%d').date()
            start = start - timedelta(days=(start.weekday() + 1) % 7)
        except Exception:
            start = None
    else:
        start = None
    if start is None:
        # 默认显示当前日期所在的周
        today = date.today()
        start = today - timedelta(days=(today.weekday() + 1) % 7)
    days = [start + timedelta(days=i) for i in range(5)]  # 周日~周四
    rows = NightShift.query.filter_by(semester_id=sid) \
        .filter(NightShift.shift_date.in_(days)).all()
    grid = {}
    for r in rows:
        grid.setdefault(r.class_id, {})[r.shift_date] = r
    class_ids = sorted(grid.keys(), key=_class_room_sort_key)
    # 整日不排标记：该日期有记录且全部为 absent（软标记不删数据，可随时恢复）
    day_recs = {}
    for r in rows:
        day_recs.setdefault(r.shift_date, []).append(r)
    days_off = {}
    for d in days:
        recs = day_recs.get(d, [])
        days_off[d] = bool(recs) and all(x.status == 'absent' for x in recs)
    # 周统计：每位教师本周节数
    week_stat = {}
    for r in rows:
        if r.status != 'absent':
            week_stat[teacher_name(r.teacher_id)] = week_stat.get(teacher_name(r.teacher_id), 0) + 1
    week_stat = sorted(week_stat.items(), key=lambda x: -x[1])
    # 4 周周期补助（全学期）
    periods_info = []
    period_nos = []
    all_rows = NightShift.query.filter_by(semester_id=sid).filter(NightShift.status != 'absent').all()
    if sem:
        sem_sun = sem.start_date - timedelta(days=(sem.start_date.weekday() + 1) % 7)
        d = sem.start_date
        week_of = {}
        while d <= sem.end_date:
            week_of[d] = ((d - sem_sun).days // 7) + 1
            d += timedelta(days=1)
        period_teacher = {}
        for r in all_rows:
            wno = week_of.get(r.shift_date)
            if wno:
                pno = (wno - 1) // 4 + 1
                period_teacher[(pno, teacher_name(r.teacher_id))] = \
                    period_teacher.get((pno, teacher_name(r.teacher_id)), 0) + 1
        period_nos = sorted({p for p, _ in period_teacher})
        for pno in period_nos:
            arr = [{'name': n, 'count': c, 'amount': round(c * unit, 2)}
                   for (p, n), c in sorted(period_teacher.items(), key=lambda x: -x[1]) if p == pno]
            periods_info.append((pno, arr))
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    prev_start = start - timedelta(days=7)
    next_start = start + timedelta(days=7)
    week_no = ''
    semester_start = sem.start_date if sem else None
    if semester_start:
        # 第 1 周 = 包含学期开始日的那一周（以该周周日为基准），之后每周 +1
        sem_sun = semester_start - timedelta(days=(semester_start.weekday() + 1) % 7)
        week_no = max(1, ((start - sem_sun).days // 7) + 1)
    return render_template('night_stats.html', grid=grid, class_ids=class_ids, days=days,
                           start=start, prev_start=prev_start, next_start=next_start,
                           week_no=week_no, teachers=teachers,
                           week_stat=week_stat, periods_info=periods_info,
                           period_nos=period_nos, unit=unit, days_off=days_off,
                           cur_period=_current_period_no(sid))


@app.route('/night/stats/week')
@login_required
def night_stats_week():
    """某教师某周的夜自习明细（供统计页点击修改）"""
    sid = get_current_semester_id()
    tid = request.args.get('tid', '').strip()
    start_str = request.args.get('start', '').strip()
    if not tid.isdigit():
        return jsonify({'ok': False, 'error': '参数错误'})
    try:
        start = datetime.strptime(start_str, '%Y-%m-%d').date()
    except Exception:
        return jsonify({'ok': False, 'error': '日期错误'})
    days = [start + timedelta(days=i) for i in range(5)]  # 周日~周四
    rows = NightShift.query.filter_by(semester_id=sid, teacher_id=int(tid)) \
        .filter(NightShift.shift_date.in_(days)).all()
    items = [{'id': r.id,
              'date': r.shift_date.strftime('%Y-%m-%d'),
              'weekday': ['周日', '周一', '周二', '周三', '周四'][r.shift_date.weekday() - 6] if r.shift_date.weekday() >= 5 else ['周一', '周二', '周三', '周四'][r.shift_date.weekday()],
              'class': class_name(r.class_id),
              'status': r.status,
              'teacher': teacher_name(r.teacher_id),
              'teacher_id': r.teacher_id} for r in rows]
    teachers = [{'id': t.id, 'name': t.name}
                for t in sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()]
    return jsonify({'ok': True, 'items': items, 'teacher': teacher_name(int(tid)),
                    'start': start.strftime('%Y-%m-%d'), 'teachers': teachers})

# ══════════════════════════════════════════════
# 加班、管理费统计
# ══════════════════════════════════════════════

@app.route('/overtimes')
@login_required
def overtimes_page():
    q = Overtime.query.filter_by(semester_id=get_current_semester_id())
    tid = request.args.get('teacher_id', '').strip()
    sd = request.args.get('start', '').strip()
    ed = request.args.get('end', '').strip()
    if not sd and not ed:
        # 默认显示当前日期所在的月
        today = date.today()
        sd = today.strftime('%Y-%m-01')
        ed = (today.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        ed = ed.strftime('%Y-%m-%d')
    if tid.isdigit():
        q = q.filter(Overtime.teacher_id == int(tid))
    if sd:
        q = q.filter(Overtime.work_date >= sd)
    if ed:
        q = q.filter(Overtime.work_date <= ed)
    rows, total, page, pages, qs = paginate(q.order_by(Overtime.work_date.desc()))
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    base = Overtime.query.filter_by(semester_id=get_current_semester_id())
    stats = {'total': base.count(),
             'hours': round(sum((x.hours or 0) for x in base.all()), 1),
             'amount': round(sum((x.amount or 0) for x in base.all()), 2)}
    return render_template('overtimes.html', rows=rows, total=total, page=page, pages=pages,
                           qs=qs, tid=tid, sd=sd, ed=ed, teachers=teachers, stats=stats)


@app.route('/overtimes/add', methods=['POST'])
@admin_required
def overtimes_add():
    teacher_id = request.form.get('teacher_id', '').strip()
    work_date = request.form.get('work_date', '').strip()
    if not teacher_id.isdigit() or not work_date:
        flash('请选择教师和日期')
        return redirect(request.referrer or url_for('overtimes_page'))
    try:
        d = datetime.strptime(work_date, '%Y-%m-%d').date()
        hours = float(request.form.get('hours', 0) or 0)
        if hours < 0 or not math.isfinite(hours):
            flash('时长必须为 0 或正数')
            return redirect(request.referrer or url_for('overtimes_page'))
    except Exception:
        flash('日期或时长格式错误')
        return redirect(request.referrer or url_for('overtimes_page'))
    amount = request.form.get('amount', '').strip()
    if not amount:
        amount = round(hours * get_setting_float('overtime_unit_price', 0), 2)
    else:
        try:
            amount = float(amount)
            if amount < 0 or not math.isfinite(amount):
                flash('金额必须为 0 或正数')
                return redirect(request.referrer or url_for('overtimes_page'))
        except Exception:
            amount = 0
    o = Overtime(semester_id=get_current_semester_id(), teacher_id=int(teacher_id),
                 work_date=d, time_range=request.form.get('time_range', '').strip(),
                 category=request.form.get('category', '周末').strip() or '周末',
                 reason=request.form.get('reason', '').strip(), hours=hours, amount=amount)
    db.session.add(o)
    db.session.commit()
    flash('加班记录已添加')
    return redirect(url_for('overtimes_page'))


@app.route('/overtimes/<int:oid>/delete', methods=['POST'])
@admin_required
def overtimes_delete(oid):
    o = db.session.get(Overtime, oid)
    if not o:
        flash('记录不存在')
        return redirect(url_for('overtimes_page'))
    db.session.delete(o)
    db.session.commit()
    flash('加班记录已删除')
    return redirect(url_for('overtimes_page'))


@app.route('/fees')
@login_required
def fees_page():
    q = ManagementFee.query.filter_by(semester_id=get_current_semester_id())
    tid = request.args.get('teacher_id', '').strip()
    ym = request.args.get('month', '').strip()
    if not ym:
        # 默认显示当前日期所在的月
        ym = date.today().strftime('%Y-%m')
    if tid.isdigit():
        q = q.filter(ManagementFee.teacher_id == int(tid))
    if ym and ym != 'all':
        q = q.filter(ManagementFee.month.like(ym + '%'))
    rows, total, page, pages, qs = paginate(q.order_by(ManagementFee.month.desc()))
    teachers = sem_filter(Teacher.query).filter_by(is_active=True).order_by(Teacher.name).all()
    base = ManagementFee.query.filter_by(semester_id=get_current_semester_id())
    stats = {'total': base.count(),
             'amount': round(sum((x.amount or 0) for x in base.all()), 2)}
    return render_template('fees.html', rows=rows, total=total, page=page, pages=pages,
                           qs=qs, tid=tid, ym=ym, teachers=teachers, stats=stats)


@app.route('/fees/add', methods=['POST'])
@admin_required
def fees_add():
    teacher_id = request.form.get('teacher_id', '').strip()
    if not teacher_id.isdigit():
        flash('请选择教师')
        return redirect(request.referrer or url_for('fees_page'))
    try:
        amount = float(request.form.get('amount', 0) or 0)
        if amount < 0 or not math.isfinite(amount):
            flash('金额必须为 0 或正数')
            return redirect(request.referrer or url_for('fees_page'))
    except Exception:
        amount = 0
    db.session.add(ManagementFee(semester_id=get_current_semester_id(), teacher_id=int(teacher_id),
                                 fee_type=request.form.get('fee_type', '班主任费').strip() or '班主任费',
                                 month=request.form.get('month', '').strip(),
                                 amount=amount, note=request.form.get('note', '').strip()))
    db.session.commit()
    flash('管理费记录已添加')
    return redirect(url_for('fees_page'))


@app.route('/fees/<int:fid>/delete', methods=['POST'])
@admin_required
def fees_delete(fid):
    f = db.session.get(ManagementFee, fid)
    if not f:
        flash('记录不存在')
        return redirect(url_for('fees_page'))
    db.session.delete(f)
    db.session.commit()
    flash('管理费记录已删除')
    return redirect(url_for('fees_page'))

# ══════════════════════════════════════════════
# 综合报表（管理员 + 领导可看）
# ══════════════════════════════════════════════

def report_data(sid):
    """汇总所有补助数据，返回 明细表 + 合计"""
    # 超课时
    wl, weeks = workload_rows(sid)
    wl_map = {r['teacher'].id: r for r in wl}
    # 看课补助
    watch_rows = LeaveRequest.query.filter_by(semester_id=sid, status='approved') \
        .filter(LeaveRequest.watch_teacher_id.isnot(None)).all()
    watch_map = {}
    for r in watch_rows:
        d = watch_map.setdefault(r.watch_teacher_id, 0.0)
        watch_map[r.watch_teacher_id] = round(d + (r.watch_amount or 0), 2)
    # 夜自习
    night_rows = NightShift.query.filter_by(semester_id=sid).filter(NightShift.status != 'absent').all()
    night_map = {}
    for r in night_rows:
        night_map[r.teacher_id] = night_map.get(r.teacher_id, 0) + 1
    night_unit = get_setting_float('night_shift_unit_price', 0)
    night_map = {k: round(v * night_unit, 2) for k, v in night_map.items()}
    # 加班
    ot_rows = Overtime.query.filter_by(semester_id=sid).all()
    ot_map = {}
    for r in ot_rows:
        ot_map[r.teacher_id] = round(ot_map.get(r.teacher_id, 0.0) + (r.amount or 0), 2)
    # 管理费
    fee_rows = ManagementFee.query.filter_by(semester_id=sid).all()
    fee_map = {}
    for r in fee_rows:
        fee_map[r.teacher_id] = round(fee_map.get(r.teacher_id, 0.0) + (r.amount or 0), 2)
    # 合并
    teacher_ids = set()
    for m in (wl_map, watch_map, night_map, ot_map, fee_map):
        teacher_ids.update(m.keys())
    rows = []
    grand_total = 0.0
    for tid in teacher_ids:
        t = db.session.get(Teacher, tid)
        name = t.name if t else teacher_name(tid)
        w = wl_map.get(tid, {}).get('amount', 0.0) if tid in wl_map else 0.0
        watch = watch_map.get(tid, 0.0)
        night = night_map.get(tid, 0.0)
        ot = ot_map.get(tid, 0.0)
        fee = fee_map.get(tid, 0.0)
        total = round(w + watch + night + ot + fee, 2)
        grand_total += total
        rows.append({'tid': tid, 'name': name, 'extra': w, 'watch': watch,
                     'night': night, 'overtime': ot, 'fee': fee, 'total': total})
    rows.sort(key=lambda x: -x['total'])
    return rows, round(grand_total, 2)


def _export_workbook(sheets):
    """sheets: [(标题, 表头, 数据行)] → BytesIO（统一导出样式：宋体、细边框、居中、自适应列宽）"""
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, Border, Side
    thin = Side(style='thin')
    border = Border(left=thin, top=thin, right=thin, bottom=thin)
    wb = Workbook()
    first = True
    for title, headers, rows in sheets:
        ws = wb.active if first else wb.create_sheet()
        first = False
        ws.title = title[:31]
        ws.append(headers)
        for c in ws[1]:
            c.font = Font(name='宋体', size=12, bold=True)
            c.alignment = Alignment(horizontal='center', vertical='center')
            c.border = border
        for r in rows:
            ws.append(r)
        for row in ws.iter_rows(min_row=2):
            for c in row:
                c.font = Font(name='宋体', size=11)
                c.alignment = Alignment(horizontal='center', vertical='center')
                c.border = border
        for col in ws.columns:
            try:
                width = max(len(str(c.value or '')) for c in col[:20]) + 2
                ws.column_dimensions[col[0].column_letter].width = min(max(width, 8), 30)
            except Exception:
                pass
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return bio


@app.route('/reports/export/night')
@login_required
def night_export():
    """夜自习统计导出"""
    sid = get_current_semester_id()
    rows = NightShift.query.filter_by(semester_id=sid).filter(NightShift.status != 'absent').all()
    unit = get_setting_float('night_shift_unit_price', 0)
    by_teacher = {}
    for r in rows:
        by_teacher[teacher_name(r.teacher_id)] = by_teacher.get(teacher_name(r.teacher_id), 0) + 1
    data = [(k, v, round(v * unit, 2)) for k, v in sorted(by_teacher.items(), key=lambda x: -x[1])]
    data.append(('合计', sum(v for _, v in by_teacher.items()), round(sum(v for _, v in by_teacher.items()) * unit, 2)))
    bio = _export_workbook([('夜自习统计', ['教师', '节数', '补助(元)'], data)])
    return send_file(bio, as_attachment=True, download_name='夜自习统计.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/reports/export/overtimes')
@login_required
def overtimes_export():
    """加班明细导出"""
    sid = get_current_semester_id()
    rows = Overtime.query.filter_by(semester_id=sid).order_by(Overtime.work_date.desc()).all()
    data = [(r.work_date.strftime('%Y-%m-%d') if r.work_date else '', teacher_name(r.teacher_id),
             r.hours or 0, r.amount or 0, r.reason or '') for r in rows]
    data.append(('合计', '', round(sum((r.hours or 0) for r in rows), 1),
                 round(sum((r.amount or 0) for r in rows), 2), ''))
    bio = _export_workbook([('加班明细', ['日期', '教师', '时长(小时)', '金额(元)', '备注'], data)])
    return send_file(bio, as_attachment=True, download_name='加班明细.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/reports/export/fees')
@login_required
def fees_export():
    """管理费明细导出"""
    sid = get_current_semester_id()
    rows = ManagementFee.query.filter_by(semester_id=sid).order_by(ManagementFee.month.desc()).all()
    data = [(r.month, teacher_name(r.teacher_id), r.fee_type or '', r.amount or 0, r.note or '') for r in rows]
    data.append(('合计', '', '', round(sum((r.amount or 0) for r in rows), 2), ''))
    bio = _export_workbook([('管理费明细', ['月份', '教师', '类型', '金额(元)', '备注'], data)])
    return send_file(bio, as_attachment=True, download_name='管理费明细.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/reports')
@login_required
def reports_page():
    sid = get_current_semester_id()
    rows, grand_total = report_data(sid)
    unit = get_setting_float('extra_hour_unit_price', 0)
    watch_unit = get_setting_float('watch_unit_price', 0)
    night_unit = get_setting_float('night_shift_unit_price', 0)
    return render_template('reports.html', rows=rows, grand_total=grand_total,
                           unit=unit, watch_unit=watch_unit, night_unit=night_unit)


@app.route('/reports/export')
@login_required
def reports_export():
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, PatternFill
    sid = get_current_semester_id()
    rows, grand_total = report_data(sid)
    sem = get_semester()
    wb = Workbook()
    ws = wb.active
    ws.title = '补助汇总'
    school = get_setting('school_name', '')
    ws.append([f'{school} 补助汇总表'])
    ws.append([f'学期：{sem.name if sem else ""}    导出时间：{datetime.now().strftime("%Y-%m-%d %H:%M")}'])
    ws.append([])
    ws.append(['教师', '超课时费(元)', '看课补助(元)', '夜自习补贴(元)', '加班费(元)', '管理费(元)', '合计(元)'])
    for r in rows:
        ws.append([r['name'], r['extra'], r['watch'], r['night'], r['overtime'], r['fee'], r['total']])
    ws.append(['合计', round(sum(r['extra'] for r in rows), 2), round(sum(r['watch'] for r in rows), 2),
               round(sum(r['night'] for r in rows), 2), round(sum(r['overtime'] for r in rows), 2),
               round(sum(r['fee'] for r in rows), 2), grand_total])
    _apply_uniform_style(ws, header_row=4)
    for c in ws[ws.max_row]:
        c.font = Font(name='宋体', size=11, bold=True)
    for col, w in zip('ABCDEFG', [12, 12, 12, 12, 12, 12, 12]):
        ws.column_dimensions[col].width = w
    # 明细 sheet：超课时
    wl, weeks = workload_rows(sid)
    ws2 = wb.create_sheet('超课时明细')
    ws2.append(['教师', '职务', '周课时', '折算周课时', '学期实际', '标准课时', '超课时', '金额'])
    for r in wl:
        ws2.append([r['teacher'].name, r['teacher'].position, r['weekly_raw'], r['weekly_coef'],
                    r['actual'], r['std_total'], r['extra'], r['amount']])
    _apply_uniform_style(ws2, header_row=1)
    # 明细 sheet：看课记录
    ws3 = wb.create_sheet('看课记录')
    ws3.append(['日期', '请假教师', '节次', '看课教师', '金额(元)'])
    watch_rows = LeaveRequest.query.filter_by(semester_id=sid, status='approved') \
        .filter(LeaveRequest.watch_teacher_id.isnot(None)).order_by(LeaveRequest.leave_date).all()
    for r in watch_rows:
        ws3.append([r.leave_date.strftime('%Y-%m-%d'), teacher_name(r.teacher_id),
                    '、'.join(str(p) for p in r.period_list()), teacher_name(r.watch_teacher_id), r.watch_amount or 0])
    _apply_uniform_style(ws3, header_row=1)
    # 明细 sheet：夜自习
    ws4 = wb.create_sheet('夜自习明细')
    ws4.append(['日期', '班级', '教师', '状态'])
    night_rows = NightShift.query.filter_by(semester_id=sid).order_by(NightShift.shift_date).all()
    for r in night_rows:
        ws4.append([r.shift_date.strftime('%Y-%m-%d'), class_name(r.class_id), teacher_name(r.teacher_id),
                    {'scheduled': '已排班', 'confirmed': '已确认', 'absent': '缺勤'}.get(r.status, r.status)])
    _apply_uniform_style(ws4, header_row=1)
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=f'补助汇总_{datetime.now().strftime("%Y%m%d")}.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# ══════════════════════════════════════════════
# 系统设置
# ══════════════════════════════════════════════

SETTING_DEFS = [
    ('school_name', '榆中县职业技术学校', '学校名称（报表抬头）'),
    ('workdays', '5', '每周上课天数（5/6/7，排课用；教学周按自然周计算不受此影响）'),
    ('periods_per_day', '8', '每天节数（排课用）'),
    ('watch_unit_price', '15', '顶课补助单价（换课上课/调课看班，元/节）'),
    ('night_shift_unit_price', '20', '夜自习补贴单价（元/次）'),
    ('extra_hour_unit_price', '25', '超课时单价（元/节）'),
    ('overtime_unit_price', '30', '加班单价（元/小时，未填金额时自动计算）'),
]

@app.route('/settings')
@admin_required
def settings_page():
    vals = {}
    for key, default, _ in SETTING_DEFS:
        vals[key] = get_setting(key, default)
    return render_template('settings.html', defs=SETTING_DEFS, vals=vals)


@app.route('/settings/save', methods=['POST'])
@admin_required
def settings_save():
    for key, default, _ in SETTING_DEFS:
        val = request.form.get(key, '').strip()
        if key in ('workdays', 'periods_per_day') and not re.match(r'^\d+$', val):
            continue
        s = Setting.query.filter_by(key=key).first()
        if s:
            s.value = val
        else:
            db.session.add(Setting(key=key, value=val))
    db.session.commit()
    flash('设置已保存')
    return redirect(url_for('settings_page'))

# ══════════════════════════════════════════════
# 数据导入（班级/教师/课程/教学任务/课表）
# ══════════════════════════════════════════════

import import_parser

IMPORT_TMP = os.path.join(BASE_DIR, 'instance', 'import_tmp')
os.makedirs(IMPORT_TMP, exist_ok=True)


def _preview_path():
    return os.path.join(IMPORT_TMP, 'preview_%s.json' % session.get('user_id', '0'))


def _infer_grade(name):
    """班级名称年份 → 入学年级（'2025供用电焊接班'/'25新能源汽修班' → '2025级'；'24机电班' → '2024级'）"""
    m = re.match(r'^20(\d{2})', name or '')
    if m:
        return '20%s级' % m.group(1)
    m = re.match(r'^(\d{2})', name or '')
    return '20%s级' % m.group(1) if m else ''


def _infer_course_category(name):
    """按课程名推断类别（导入默认值，可后续手动改）"""
    if any(k in name for k in ['实训', '技能训练', '实习', '操作', '实践']):
        return '实训课'
    if any(k in name for k in ['语文', '数学', '英语', '政治', '历史', '地理', '物理', '化学',
                               '生物', '思政', '体育', '音乐', '美术', '班会', '心理健康',
                               '职业生涯', '就业指导', '礼仪', '书法']):
        return '文化课'
    return '专业课'


def _parse_venue(venue):
    """解析场地要求 → (name_part, building, room_no, ctype)
    '机房七(敦403)' → ('机房七', '敦', '403', '机房')；'机房一' → ('机房一', '', '', '机房')"""
    v = (venue or '').strip()
    m = re.match(r'^(.*?)[\(（]([^()（）]*)[\)）]$', v)
    if m:
        name_part = m.group(1).strip()
        loc = m.group(2).strip()
        mm = re.match(r'^(\D+?)(\d.*)$', loc)
        building = mm.group(1) if mm else loc
        room_no = mm.group(2) if mm else ''
    else:
        name_part = v
        # '笃101' → 楼名'笃' + 门牌号'101'；'机房一'（中文数字）保持整体
        mm = re.match(r'^(\D+?)(\d+.*)$', v)
        building = mm.group(1) if mm else ''
        room_no = mm.group(2) if mm else ''
    if '机房' in name_part or '机房' in v:
        ctype = '机房'
    elif '实训' in name_part or '实训' in v:
        ctype = '实训室'
    else:
        ctype = '普通教室'
    return name_part, building, room_no, ctype


def _match_or_create_room(sid, venue):
    """按场地要求匹配教室；没有则自动创建（读出楼名/门牌号），返回 (room, created)"""
    if not venue:
        return None, False
    name_part, building, room_no, ctype = _parse_venue(venue)
    # 1) 名称包含匹配
    for r in Classroom.query.filter_by(semester_id=sid).all():
        if name_part and name_part in r.name:
            return r, False
    # 2) 楼名+门牌号匹配
    if building and room_no:
        for r in Classroom.query.filter_by(semester_id=sid).all():
            if r.building and r.building in building and r.room_no == room_no:
                return r, False
    # 3) 自动创建
    full_name = (building + room_no) if (building or room_no) else name_part
    if not full_name:
        return None, False
    rm = Classroom(semester_id=sid, name=full_name, building=building,
                   room_no=room_no, ctype=ctype, capacity=50,
                   remark=name_part if name_part != full_name else '')
    db.session.add(rm)
    db.session.flush()
    return rm, True


def _do_import(data, sid):
    """执行导入（班级/教师/课程/教学任务/课表），返回统计与提示"""
    stats = {'classes': 0, 'teachers': 0, 'courses': 0, 'tasks': 0, 'cells': 0}
    notes = []
    cp = data.get('class_plan') or {}
    # 1. 班级（入学年份=名称前两位；班主任=班会课教师）
    banhui_teacher = {}
    for t in cp.get('tasks', []):
        if '班会' in t.get('course', '') and t['class'] not in banhui_teacher:
            banhui_teacher[t['class']] = t['teacher']
    for name in cp.get('classes', []):
        if not ClassInfo.query.filter_by(semester_id=sid, name=name).first():
            db.session.add(ClassInfo(semester_id=sid, name=name,
                                     grade=_infer_grade(name),
                                     head_teacher=banhui_teacher.get(name, '')))
            stats['classes'] += 1
    # 2. 教师（班级计划表 + 教师计划表 并集），学科类别按所教课程自动推断
    teacher_names = list(cp.get('teachers', []))
    for name in (data.get('teacher_plan') or {}).get('teachers', []):
        if name not in teacher_names:
            teacher_names.append(name)
    # 教师 → 课程类别统计（按课时加权）
    cat_weight = {}
    for t in cp.get('tasks', []):
        key = t['teacher']
        cat_weight.setdefault(key, {})
        cat = _infer_course_category(t['course'])
        cat_weight[key][cat] = cat_weight[key].get(cat, 0) + t.get('hours', 0)
    for name in teacher_names:
        if not Teacher.query.filter_by(semester_id=sid, name=name).first():
            cats = cat_weight.get(name, {})
            cat = max(cats.items(), key=lambda x: x[1])[0] if cats else '专业课'
            db.session.add(Teacher(semester_id=sid, name=name,
                                   position='专任教师', subject_category=cat))
            stats['teachers'] += 1
    # 3. 课程（类别自动推断；默认周课时取该课程各任务的最大值）
    course_hours = {}
    for t in cp.get('tasks', []):
        course_hours.setdefault(t['course'], []).append(t.get('hours', 0))
    for name in cp.get('courses', []):
        if not Course.query.filter_by(semester_id=sid, name=name).first():
            hours = max(course_hours.get(name, [0])) or 4
            db.session.add(Course(semester_id=sid, name=name,
                                  category=_infer_course_category(name),
                                  default_weekly_hours=int(hours)))
            stats['courses'] += 1
    db.session.flush()
    # 4. 教学任务（含场地→教室匹配）
    for t in cp.get('tasks', []):
        if t.get('hours', 0) <= 0:
            continue
        cls = ClassInfo.query.filter_by(semester_id=sid, name=t['class']).first()
        co = Course.query.filter_by(semester_id=sid, name=t['course']).first()
        tc = Teacher.query.filter_by(semester_id=sid, name=t['teacher']).first()
        if not cls or not co or not tc:
            continue
        dup = [x for x in TeachingTask.query.filter_by(semester_id=sid, course_id=co.id, teacher_id=tc.id).all()
               if cls.id in x.classes()]
        if dup:
            # 已存在：若之前未匹配到教室、而本次能匹配到，则补挂教室
            if not dup[0].classroom_id and t.get('venue'):
                rm, created = _match_or_create_room(sid, t['venue'])
                if rm:
                    dup[0].classroom_id = rm.id
                    if created:
                        notes.append('自动创建教室「%s」' % rm.name)
            continue
        room_id = None
        if t.get('venue'):
            rm, created = _match_or_create_room(sid, t['venue'])
            if rm:
                room_id = rm.id
                if created:
                    notes.append('自动创建教室「%s」（场地：%s）' % (rm.name, t['venue']))
        db.session.add(TeachingTask(semester_id=sid, class_ids=json.dumps([cls.id]),
                                    course_id=co.id, teacher_id=tc.id,
                                    weekly_hours=int(t['hours']), classroom_id=room_id))
        stats['tasks'] += 1
    # 5. 班级课表（导入前清空当前学期现有课表；课表中的课程/教师若不存在则自动补建；
    #    机房课第二行是场地而非教师，教师从计划表对应任务补全）
    if data.get('class_schedule'):
        ScheduleCell.query.filter_by(semester_id=sid).delete()
        # 清理历史误建的"机房N"教师（无任务引用时删除）
        for t in Teacher.query.filter_by(semester_id=sid).all():
            if '机房' in t.name and not TeachingTask.query.filter_by(semester_id=sid, teacher_id=t.id).count():
                db.session.delete(t)
        db.session.flush()
        # (班级, 课程) → 教师 映射（来自班级计划表，用于机房课补全教师）
        task_teacher_map = {}
        for t in cp.get('tasks', []):
            task_teacher_map.setdefault((t['class'], t['course']), t['teacher'])
        for cname, info in data['class_schedule'].items():
            cls = ClassInfo.query.filter_by(semester_id=sid, name=cname).first()
            if not cls:
                notes.append('课表班级「%s」未在计划表中，已跳过' % cname)
                continue
            cells = info.get('cells', [])
            # 班级本班教室自动关联（课表标题里的"教室:笃XXX"）
            if info.get('room') and not cls.classroom_id:
                rm, created = _match_or_create_room(sid, info['room'])
                if rm:
                    cls.classroom_id = rm.id
                    if created:
                        notes.append('自动创建本班教室「%s」（%s）' % (rm.name, cname))
            for cell in cells:
                co = Course.query.filter_by(semester_id=sid, name=cell['course']).first()
                if not co:
                    co = Course(semester_id=sid, name=cell['course'],
                                category=_infer_course_category(cell['course']))
                    db.session.add(co)
                    db.session.flush()
                    stats['courses'] += 1
                    notes.append('课表新增课程「%s」（计划表未含，已自动创建）' % cell['course'])
                # 教师：格子第二行 或 计划表对应任务
                tname = cell.get('teacher') or task_teacher_map.get((cname, cell['course']))
                tc = None
                if tname:
                    tc = Teacher.query.filter_by(semester_id=sid, name=tname).first()
                    if not tc:
                        tc = Teacher(semester_id=sid, name=tname,
                                     position='专任教师', subject_category='专业课')
                        db.session.add(tc)
                        db.session.flush()
                        stats['teachers'] += 1
                if not co or not tc:
                    continue
                # 场地 → 教室（自动创建）
                room_id = None
                if cell.get('venue'):
                    rm, created = _match_or_create_room(sid, cell['venue'])
                    if rm:
                        room_id = rm.id
                        if created:
                            notes.append('自动创建教室「%s」' % rm.name)
                db.session.add(ScheduleCell(semester_id=sid, class_id=cls.id,
                                            weekday=cell['weekday'], period=cell['period'],
                                            course_id=co.id, teacher_id=tc.id,
                                            classroom_id=room_id, week_type='every'))
                stats['cells'] += 1
    db.session.commit()
    return stats, notes


@app.route('/import', methods=['GET'])
@admin_required
def import_page():
    """数据导入已统一到「数据管理」"""
    return redirect(url_for('data_management'))


@app.route('/import/do', methods=['POST'])
@admin_required
def import_do():
    """上传文件 → 自动识别 → 自动导入（一步完成）"""
    files = request.files.getlist('files')
    if not files:
        flash('请选择要上传的 Excel 文件')
        return redirect(url_for('import_page'))
    sid = get_current_semester_id()
    if not sid:
        flash('请先在「学期管理」中创建当前学期')
        return redirect(url_for('import_page'))
    data = {}
    notes_all = []
    for f in files:
        if not f or not f.filename:
            continue
        ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
        if ext not in ('xlsx', 'xls'):
            flash(f'「{f.filename}」不是 Excel 文件，已跳过')
            continue
        path = os.path.join(IMPORT_TMP, 'imp_%s_%s.%s' % (int(time.time()), uuid.uuid4().hex[:6], ext))
        f.save(path)
        fn = f.filename
        try:
            if '班级课程计划' in fn:
                cls, tasks = import_parser.parse_class_plan(path)
                data['class_plan'] = {'classes': cls, 'tasks': tasks,
                                      'courses': sorted(set(t['course'] for t in tasks)),
                                      'teachers': sorted(set(t['teacher'] for t in tasks)),
                                      'venues': sorted(set(t['venue'] for t in tasks if t['venue']))}
            elif '教师课程计划' in fn:
                teachers, tasks = import_parser.parse_teacher_plan(path)
                data['teacher_plan'] = {'teachers': teachers, 'tasks': tasks}
            elif '班级课程表' in fn:
                data['class_schedule'] = import_parser.parse_class_schedule(path)
            elif '教师课程表' in fn:
                data['teacher_schedule'] = import_parser.parse_teacher_schedule(path)
            else:
                flash(f'「{fn}」无法识别类型（文件名需含：班级课程计划表/教师课程计划表/班级课程表/教师课程表）')
                continue
            os.remove(path)
        except Exception as e:
            flash(f'「{fn}」解析失败：{e}')
            try:
                os.remove(path)
            except Exception:
                pass
    if not data:
        flash('没有成功解析的文件，请确认文件名包含「班级课程计划表/教师课程计划表/班级课程表/教师课程表」关键词')
        return redirect(url_for('import_page'))
    # 自动导入
    stats, notes = _do_import(data, sid)
    notes_all.extend(notes)
    session['import_result'] = {
        'classes': stats['classes'], 'teachers': stats['teachers'],
        'courses': stats['courses'], 'tasks': stats['tasks'], 'cells': stats['cells'],
        'notes': notes_all[:20],
    }
    flash(f'导入完成：班级+{stats["classes"]}，教师+{stats["teachers"]}，课程+{stats["courses"]}，'
          f'教学任务+{stats["tasks"]}，课表格子{stats["cells"]} 个')
    return redirect(url_for('import_page'))
# ══════════════════════════════════════════════
# 主入口
# ══════════════════════════════════════════════

def _run_db_migrations():
    """启动时迁移：为旧数据库补充新增列（ALTER TABLE，已存在则跳过）"""
    try:
        if trim_pkgvar:
            db_file = os.path.join(trim_pkgvar, 'edu_admin.db')
        else:
            db_file = os.path.join(BASE_DIR, 'instance', 'edu_admin.db')
        if not os.path.exists(db_file):
            return
        import sqlite3
        conn = sqlite3.connect(db_file)
        cur = conn.cursor()
        for col, typ in [('building', 'VARCHAR(64)'), ('room_no', 'VARCHAR(32)')]:
            try:
                cur.execute(f'ALTER TABLE classroom ADD COLUMN {col} {typ} DEFAULT ""')
            except Exception:
                pass  # 已存在
        try:
            cur.execute('ALTER TABLE class_info ADD COLUMN classroom_id INTEGER DEFAULT NULL')
        except Exception:
            pass  # 已存在
        try:
            cur.execute('ALTER TABLE book_stock_log ADD COLUMN semester_id INTEGER DEFAULT 0')
        except Exception:
            pass  # 已存在
        try:
            cur.execute('ALTER TABLE leave_request ADD COLUMN leave_type VARCHAR(8) DEFAULT "调课"')
        except Exception:
            pass  # 已存在
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS payment (id INTEGER PRIMARY KEY AUTOINCREMENT, semester_id INTEGER NOT NULL, period_no INTEGER DEFAULT 1, teacher_id INTEGER NOT NULL, category VARCHAR(16) NOT NULL, amount FLOAT DEFAULT 0, source VARCHAR(8) DEFAULT "auto", note VARCHAR(64) DEFAULT "", created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        except Exception:
            pass
        try:
            cur.execute('ALTER TABLE order_plan ADD COLUMN major VARCHAR(32) DEFAULT ""')
        except Exception:
            pass
        try:
            cur.execute('ALTER TABLE order_plan ADD COLUMN semester_no INTEGER DEFAULT 1')
        except Exception:
            pass
        conn.commit()
        conn.close()
    except Exception:
        pass


def init_defaults():
    """首次启动初始化默认数据"""
    with app.app_context():
        db.create_all()
        _run_db_migrations()
        if User.query.count() == 0:
            u = User(username='admin', role=ROLE_ADMIN, display_name='管理员')
            u.set_password('admin123')
            db.session.add(u)
        pos_defaults = [('专任教师', 12), ('教研室主任', 8), ('中层干部', 6), ('行政兼课', 4)]
        for name, hours in pos_defaults:
            if not PositionStandard.query.filter_by(position=name).first():
                db.session.add(PositionStandard(position=name, weekly_std_hours=hours))
        coef_defaults = [('文化课', 1.0), ('专业课', 1.0), ('实训课', 0.9), ('公共课', 1.0), ('体育', 1.0)]
        for cat, coef in coef_defaults:
            if not CourseCoefficient.query.filter_by(category=cat).first():
                db.session.add(CourseCoefficient(category=cat, coefficient=coef))
        for key, default, remark in SETTING_DEFS:
            if not Setting.query.filter_by(key=key).first():
                db.session.add(Setting(key=key, value=default, remark=remark))
        db.session.commit()


if __name__ == '__main__':
    init_defaults()
    port = int(os.environ.get('PORT', 5801))
    print(f'教务管理系统启动 http://127.0.0.1:{port}')
    try:
        from waitress import serve
        serve(app, host='0.0.0.0', port=port, threads=16)
    except ImportError:
        app.run(host='0.0.0.0', port=port, debug=False)
