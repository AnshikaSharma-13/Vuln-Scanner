from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vulnscanner-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnscanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ─── MODELS ──────────────────────────────────────────────────────────────────

class User(db.Model, UserMixin):
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80), unique=True, nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(200), nullable=False)
    is_admin   = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans      = db.relationship('ScanResult', backref='user', lazy=True, cascade='all, delete-orphan')

class ScanResult(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_url   = db.Column(db.String(500), nullable=False)
    scan_type    = db.Column(db.String(50), nullable=False)   # port / xss / header / sqli
    severity     = db.Column(db.String(20), nullable=False)   # high / medium / low
    findings     = db.Column(db.Text, nullable=False)
    raw_details  = db.Column(db.Text, nullable=False)
    scanned_at   = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ─── SCANNERS ────────────────────────────────────────────────────────────────
import socket, requests, re
from urllib.parse import urlparse

def scan_ports(url):
    parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    host   = parsed.hostname or parsed.path
    common_ports = {
        21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
        80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS',
        445:'SMB', 3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL',
        6379:'Redis', 8080:'HTTP-Alt', 8443:'HTTPS-Alt', 27017:'MongoDB'
    }
    open_ports, details = [], []
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    for port, service in common_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            s.close()
            if result == 0:
                open_ports.append({'port': port, 'service': service})
                details.append(f"Port {port} ({service}) - OPEN")
        except Exception:
            pass

    dangerous = {21,23,445,3306,3389,27017,6379}
    if any(p['port'] in dangerous for p in open_ports):
        severity = 'high'
        findings = f"Dangerous open ports detected: {[p['port'] for p in open_ports if p['port'] in dangerous]}"
    elif len(open_ports) > 5:
        severity = 'medium'
        findings = f"{len(open_ports)} open ports found – attack surface is large"
    elif open_ports:
        severity = 'low'
        findings = f"{len(open_ports)} open port(s) found – minimal risk"
    else:
        severity = 'low'
        findings = "No open ports detected from common list"

    return severity, findings, '\n'.join(details) if details else 'No open ports found'

def scan_xss(url):
    payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
    ]
    vulnerable, details = [], []
    base = url if url.startswith('http') else 'http://' + url
    csp   = ''   # default so it's always defined
    x_xss = ''

    try:
        resp = requests.get(base, timeout=5, verify=False)
        details.append(f"Target: {base} [HTTP {resp.status_code}]")

        csp   = resp.headers.get('Content-Security-Policy', '')
        x_xss = resp.headers.get('X-XSS-Protection', '')

        for payload in payloads:
            test_url = f"{base}?q={requests.utils.quote(payload)}"
            try:
                r = requests.get(test_url, timeout=5, verify=False)
                if payload.lower() in r.text.lower():
                    vulnerable.append(payload)
                    details.append(f"VULNERABLE to: {payload}")
                else:
                    details.append(f"Safe against: {payload[:40]}...")
            except Exception as e:
                details.append(f"Error testing payload: {e}")

        if not csp:
            details.append("WARNING: No Content-Security-Policy header found")
        if not x_xss:
            details.append("WARNING: No X-XSS-Protection header found")

    except Exception as e:
        details.append(f"Connection error: {e}")

    if vulnerable:
        severity = 'high'
        findings = f"XSS vulnerabilities confirmed with {len(vulnerable)} payload(s)"
    elif not csp:
        severity = 'medium'
        findings = "No XSS confirmed but missing security headers increase risk"
    else:
        severity = 'low'
        findings = "No reflected XSS detected; security headers present"

    return severity, findings, '\n'.join(details)

def scan_headers(url):
    base = url if url.startswith('http') else 'http://' + url
    security_headers = {
        'Strict-Transport-Security': 'Enforces HTTPS connections',
        'Content-Security-Policy': 'Prevents XSS and injection attacks',
        'X-Frame-Options': 'Prevents clickjacking',
        'X-Content-Type-Options': 'Prevents MIME sniffing',
        'X-XSS-Protection': 'Browser XSS filter',
        'Referrer-Policy': 'Controls referrer info',
        'Permissions-Policy': 'Controls browser features',
    }
    missing, present, details = [], [], []

    try:
        resp = requests.get(base, timeout=5, verify=False)
        details.append(f"Target: {base} [HTTP {resp.status_code}]")
        details.append(f"Server: {resp.headers.get('Server','Unknown')}")
        details.append("─" * 40)

        for header, desc in security_headers.items():
            val = resp.headers.get(header)
            if val:
                present.append(header)
                details.append(f"✓ {header}: {val}")
            else:
                missing.append(header)
                details.append(f"✗ MISSING: {header} ({desc})")

        server = resp.headers.get('Server', '')
        if server:
            details.append(f"\nINFO: Server banner exposed: {server}")
        powered = resp.headers.get('X-Powered-By', '')
        if powered:
            details.append(f"INFO: X-Powered-By exposed: {powered}")
    except Exception as e:
        details.append(f"Connection error: {e}")
        missing = list(security_headers.keys())

    score = len(present) / len(security_headers)
    if score < 0.4:
        severity = 'high'
        findings = f"{len(missing)} critical security headers missing ({', '.join(missing[:3])}...)"
    elif score < 0.7:
        severity = 'medium'
        findings = f"{len(missing)} security headers missing – partial hardening"
    else:
        severity = 'low'
        findings = f"Good header coverage – only {len(missing)} header(s) missing"

    return severity, findings, '\n'.join(details)

def scan_sqli(url):
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR "1"="1',
        "'; DROP TABLE users--",
        "1' AND SLEEP(2)--",
        "' UNION SELECT NULL--",
    ]
    errors = [
        'sql syntax', 'mysql_fetch', 'ora-', 'pg_query',
        'sqlite_', 'syntax error', 'odbc', 'jdbc',
        'microsoft ole db', 'unclosed quotation', 'quoted string not properly terminated'
    ]
    vulnerable, details = [], []
    base = url if url.startswith('http') else 'http://' + url

    try:
        resp = requests.get(base, timeout=5, verify=False)
        details.append(f"Target: {base} [HTTP {resp.status_code}]")

        for payload in payloads:
            test_url = f"{base}?id={requests.utils.quote(payload)}"
            try:
                r = requests.get(test_url, timeout=5, verify=False)
                body = r.text.lower()
                found_errors = [e for e in errors if e in body]
                if found_errors:
                    vulnerable.append(payload)
                    details.append(f"VULNERABLE: '{payload}' triggered SQL error: {found_errors[0]}")
                else:
                    details.append(f"Safe: {payload[:40]}...")
            except Exception as e:
                details.append(f"Error testing: {e}")
    except Exception as e:
        details.append(f"Connection error: {e}")

    if vulnerable:
        severity = 'high'
        findings = f"SQL injection vulnerability confirmed! {len(vulnerable)} payload(s) triggered errors"
    else:
        severity = 'low'
        findings = "No SQL injection errors detected from standard payloads"

    return severity, findings, '\n'.join(details)

# ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        if not all([username, email, password, confirm]):
            flash('All fields are required.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
        else:
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            user   = User(username=username, email=email, password=hashed)
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        user     = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ─── USER DASHBOARD ──────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.scanned_at.desc()).limit(5).all()
    high   = ScanResult.query.filter_by(user_id=current_user.id, severity='high').count()
    medium = ScanResult.query.filter_by(user_id=current_user.id, severity='medium').count()
    low    = ScanResult.query.filter_by(user_id=current_user.id, severity='low').count()
    return render_template('dashboard.html', scans=scans, high=high, medium=medium, low=low)

@app.route('/profile')
@login_required
def profile():
    total = ScanResult.query.filter_by(user_id=current_user.id).count()
    return render_template('profile.html', total=total)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip()
    if username and username != current_user.username:
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('profile'))
        current_user.username = username
    if email and email != current_user.email:
        if User.query.filter_by(email=email).first():
            flash('Email already in use.', 'danger')
            return redirect(url_for('profile'))
        current_user.email = email
    new_pw = request.form.get('new_password', '')
    if new_pw:
        current_user.password = bcrypt.generate_password_hash(new_pw).decode('utf-8')
    db.session.commit()
    flash('Profile updated successfully.', 'success')
    return redirect(url_for('profile'))

# ─── SCANNER ROUTES ──────────────────────────────────────────────────────────

def _scan_page(scan_type, title):
    history = ScanResult.query.filter_by(user_id=current_user.id, scan_type=scan_type)\
                               .order_by(ScanResult.scanned_at.desc()).all()
    return render_template('scanner.html', scan_type=scan_type, title=title, history=history)

@app.route('/scan/port')
@login_required
def scan_port_page():    return _scan_page('port', 'Port Scanner')

@app.route('/scan/xss')
@login_required
def scan_xss_page():     return _scan_page('xss', 'XSS Scanner')

@app.route('/scan/header')
@login_required
def scan_header_page():  return _scan_page('header', 'Header Scanner')

@app.route('/scan/sqli')
@login_required
def scan_sqli_page():    return _scan_page('sqli', 'SQL Injection Scanner')

@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    data      = request.get_json()
    url       = (data.get('url') or '').strip()
    scan_type = (data.get('scan_type') or '').strip()
    if not url or not scan_type:
        return jsonify({'error': 'URL and scan type are required'}), 400

    scanners = {'port': scan_ports, 'xss': scan_xss, 'header': scan_headers, 'sqli': scan_sqli}
    if scan_type not in scanners:
        return jsonify({'error': 'Invalid scan type'}), 400

    try:
        severity, findings, raw = scanners[scan_type](url)
        result = ScanResult(
            user_id=current_user.id, target_url=url,
            scan_type=scan_type, severity=severity,
            findings=findings, raw_details=raw
        )
        db.session.add(result)
        db.session.commit()
        return jsonify({
            'id': result.id, 'severity': severity,
            'findings': findings, 'raw_details': raw,
            'scanned_at': result.scanned_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── HISTORY ─────────────────────────────────────────────────────────────────

@app.route('/history')
@login_required
def history():
    scans = ScanResult.query.filter_by(user_id=current_user.id)\
                             .order_by(ScanResult.scanned_at.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/history/download')
@login_required
def download_history():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.units import cm
    import io

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm,
                            leftMargin=2*cm, rightMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle('Title', parent=styles['Title'],
                                 fontSize=22, textColor=colors.HexColor('#0d6efd'),
                                 spaceAfter=6)
    sub_style   = ParagraphStyle('Sub', parent=styles['Normal'],
                                 fontSize=10, textColor=colors.grey, spaceAfter=16)
    h2_style    = ParagraphStyle('H2', parent=styles['Heading2'],
                                 fontSize=13, textColor=colors.HexColor('#212529'))
    body_style  = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9,
                                 leading=14, textColor=colors.HexColor('#333'))

    story.append(Paragraph("VulnScanner – Scan History Report", title_style))
    story.append(Paragraph(f"User: {current_user.username} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", sub_style))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
    story.append(Spacer(1, 12))

    scans = ScanResult.query.filter_by(user_id=current_user.id)\
                             .order_by(ScanResult.scanned_at.desc()).all()

    sev_colors = {'high': colors.HexColor('#dc3545'),
                  'medium': colors.HexColor('#fd7e14'),
                  'low': colors.HexColor('#198754')}

    for scan in scans:
        story.append(Paragraph(f"#{scan.id} – {scan.target_url}", h2_style))
        color = sev_colors.get(scan.severity, colors.grey)
        data  = [
            ['Scan Type', scan.scan_type.upper()],
            ['Severity',  scan.severity.upper()],
            ['Date',      scan.scanned_at.strftime('%Y-%m-%d %H:%M')],
            ['Findings',  scan.findings],
        ]
        t = Table(data, colWidths=[3.5*cm, 13*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR',  (1,1), (1,1), color),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,0), (-1,-1), 9),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING',    (0,0), (-1,-1), 6),
            ('VALIGN',     (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Raw Details:</b>", body_style))
        for line in scan.raw_details.split('\n')[:20]:
            story.append(Paragraph(line.replace('<','&lt;').replace('>','&gt;') or '&nbsp;', body_style))
        story.append(Spacer(1, 18))
        story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#dee2e6')))
        story.append(Spacer(1, 8))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f'vulnscan_history_{current_user.username}.pdf',
                     mimetype='application/pdf')

@app.route('/scan/<int:scan_id>/pdf')
@login_required
def download_single_pdf(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('history'))

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.units import cm
    import io

    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm,
                               leftMargin=2*cm, rightMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    sev_colors = {'high': colors.HexColor('#dc3545'),
                  'medium': colors.HexColor('#fd7e14'),
                  'low': colors.HexColor('#198754')}
    sev_color  = sev_colors.get(scan.severity, colors.grey)

    story.append(Paragraph("VulnScanner – Detailed Report", ParagraphStyle(
        'T', parent=styles['Title'], fontSize=22, textColor=colors.HexColor('#0d6efd'), spaceAfter=4)))
    story.append(Paragraph(
        f"Scan #{scan.id} | {scan.scanned_at.strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle('S', parent=styles['Normal'], fontSize=10, textColor=colors.grey, spaceAfter=16)))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
    story.append(Spacer(1, 14))

    summary = [
        ['Target URL',  scan.target_url],
        ['Scan Type',   scan.scan_type.upper()],
        ['Severity',    scan.severity.upper()],
        ['Performed By',scan.user.username],
        ['Date / Time', scan.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Findings',    scan.findings],
    ]
    t = Table(summary, colWidths=[4*cm, 12.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (0,-1), colors.HexColor('#f1f3f5')),
        ('TEXTCOLOR',   (1,2), (1,2), sev_color),
        ('FONTNAME',    (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',    (0,0), (-1,-1), 10),
        ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#ced4da')),
        ('PADDING',     (0,0), (-1,-1), 7),
        ('VALIGN',      (0,0), (-1,-1), 'TOP'),
        ('FONTNAME',    (0,0), (0,-1), 'Helvetica-Bold'),
    ]))
    story.append(t)
    story.append(Spacer(1, 18))
    story.append(Paragraph("Raw Scan Details", ParagraphStyle(
        'H2', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#212529'), spaceAfter=8)))
    story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#dee2e6')))
    story.append(Spacer(1, 6))

    body_s = ParagraphStyle('body', parent=styles['Normal'], fontSize=8.5, leading=14,
                            fontName='Courier', textColor=colors.HexColor('#333'))
    for line in scan.raw_details.split('\n'):
        story.append(Paragraph(
            (line or '&nbsp;').replace('<','&lt;').replace('>','&gt;'), body_s))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f'vulnscan_{scan.scan_type}_{scan.id}.pdf',
                     mimetype='application/pdf')

# ─── ADMIN ROUTES ────────────────────────────────────────────────────────────

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users  = User.query.filter_by(is_admin=False).count()
    high   = ScanResult.query.filter_by(severity='high').count()
    medium = ScanResult.query.filter_by(severity='medium').count()
    low    = ScanResult.query.filter_by(severity='low').count()
    recent = ScanResult.query.order_by(ScanResult.scanned_at.desc()).limit(8).all()
    return render_template('admin_dashboard.html',
                           users=users, high=high, medium=medium, low=low, recent=recent)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/scanner/<scan_type>')
@login_required
@admin_required
def admin_scanner_history(scan_type):
    valid = ['port', 'xss', 'header', 'sqli']
    if scan_type not in valid:
        flash('Invalid scanner type.', 'danger')
        return redirect(url_for('admin_dashboard'))
    scans = ScanResult.query.filter_by(scan_type=scan_type)\
                             .order_by(ScanResult.scanned_at.desc()).all()
    titles = {'port':'Port Scanner','xss':'XSS Scanner','header':'Header Scanner','sqli':'SQL Injection Scanner'}
    return render_template('admin_scanner.html', scans=scans, scan_type=scan_type, title=titles[scan_type])

# ─── CHART API ───────────────────────────────────────────────────────────────

@app.route('/api/chart/user')
@login_required
def api_chart_user():
    high   = ScanResult.query.filter_by(user_id=current_user.id, severity='high').count()
    medium = ScanResult.query.filter_by(user_id=current_user.id, severity='medium').count()
    low    = ScanResult.query.filter_by(user_id=current_user.id, severity='low').count()
    by_type = {}
    for t in ['port','xss','header','sqli']:
        by_type[t] = ScanResult.query.filter_by(user_id=current_user.id, scan_type=t).count()
    return jsonify({'high': high, 'medium': medium, 'low': low, 'by_type': by_type})

@app.route('/api/chart/admin')
@login_required
@admin_required
def api_chart_admin():
    high   = ScanResult.query.filter_by(severity='high').count()
    medium = ScanResult.query.filter_by(severity='medium').count()
    low    = ScanResult.query.filter_by(severity='low').count()
    by_type = {}
    for t in ['port','xss','header','sqli']:
        by_type[t] = ScanResult.query.filter_by(scan_type=t).count()
    return jsonify({'high': high, 'medium': medium, 'low': low, 'by_type': by_type})

# ─── INIT ────────────────────────────────────────────────────────────────────

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@vulnscanner.com').first():
            pw    = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin = User(username='admin', email='admin@vulnscanner.com',
                         password=pw, is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin created: admin@vulnscanner.com / admin123")

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)