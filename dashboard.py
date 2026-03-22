from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
import os
import json
import threading
import io
import html as html_module
from datetime import datetime
from main import start_scan
from core.storage import vulnerabilities, clear_vulns, set_status, get_status, get_progress, get_risk_score
from core.report import scan_stats, save_scan_history
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import sqlite3
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from auth.database import init_db, get_user_by_username, create_user
from auth.models import User
from auth.database import init_db, get_user_by_username, get_user_by_email, create_user, update_password
from modules.report_writer import generate_ai_report, generate_hackerone_report
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── AUTH SETUP ──
app.secret_key = "saurabh_scanner_2026_xk92pzla"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access the scanner."

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return User.from_db_row(row)

# Initialize DB on startup
init_db()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        row = get_user_by_username(username)
        user = User.from_db_row(row)

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("index"))  # ✅ goes to index now
        else:
            return render_template("login.html", error="Invalid username or password", success=None)

    return render_template("login.html", error=None, success=None)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username").strip()
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        security_question = request.form.get("security_question")
        security_answer = request.form.get("security_answer").strip().lower()

        if len(username) < 3:
            return render_template("signup.html", error="Username must be at least 3 characters", success=None)
        if len(password) < 6:
            return render_template("signup.html", error="Password must be at least 6 characters", success=None)
        if password != confirm:
            return render_template("signup.html", error="Passwords do not match", success=None)
        if not security_question:
            return render_template("signup.html", error="Please select a security question", success=None)
        if len(security_answer) < 2:
            return render_template("signup.html", error="Security answer too short", success=None)

        hashed = generate_password_hash(password)
        hashed_answer = generate_password_hash(security_answer)
        success = create_user(username, hashed, email, security_question, hashed_answer)

        if success:
            return render_template("signup.html", success="✅ Account created! You can now log in.", error=None)
        else:
            return render_template("signup.html", error="Username or email already taken", success=None)

    return render_template("signup.html", error=None, success=None)


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "GET":
        return render_template("forgot.html", step=1, error=None, success=None)

    step = int(request.form.get("step", 1))

    # ── STEP 1: find account by email ──
    if step == 1:
        email = request.form.get("email", "").strip().lower()
        row = get_user_by_email(email)
        user = User.from_db_row(row)

        if not user:
            return render_template("forgot.html", step=1,
                                   error="No account found with that email.", success=None)

        question_map = {
            "pet": "What was your first pet's name?",
            "city": "What city were you born in?",
            "school": "What was your primary school name?",
            "mother": "What is your mother's maiden name?",
            "car": "What was your first car?",
        }
        question = question_map.get(user.security_question, user.security_question)

        return render_template("forgot.html", step=2, error=None, success=None,
                               username=user.username, question=question)

    # ── STEP 2: verify security answer ──
    elif step == 2:
        username = request.form.get("username")
        answer = request.form.get("answer", "").strip().lower()
        row = get_user_by_username(username)
        user = User.from_db_row(row)

        if not user or not check_password_hash(user.security_answer, answer):
            question_map = {
                "pet": "What was your first pet's name?",
                "city": "What city were you born in?",
                "school": "What was your primary school name?",
                "mother": "What is your mother's maiden name?",
                "car": "What was your first car?",
            }
            question = question_map.get(user.security_question, "") if user else ""
            return render_template("forgot.html", step=2,
                                   error="Incorrect answer. Try again.",
                                   username=username, question=question, success=None)

        return render_template("forgot.html", step=3, error=None,
                               success=None, username=username)

    # ── STEP 3: reset password ──
    elif step == 3:
        username = request.form.get("username")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if len(new_password) < 6:
            return render_template("forgot.html", step=3,
                                   error="Password must be at least 6 characters",
                                   username=username, success=None)
        if new_password != confirm_password:
            return render_template("forgot.html", step=3,
                                   error="Passwords do not match",
                                   username=username, success=None)

        update_password(username, generate_password_hash(new_password))
        return render_template("login.html",
                               error=None,
                               success="✅ Password reset! You can now log in.")

    return redirect(url_for("forgot"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


def safe_pdf_text(text, max_len=40):
    text = str(text)
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return html_module.escape(text)


def build_pdf(target, timestamp, score, label, color, vulns):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=0.5*inch, leftMargin=0.5*inch,
        topMargin=0.5*inch, bottomMargin=0.5*inch
    )
    styles = getSampleStyleSheet()
    elements = []

    # ── TITLE ──
    elements.append(Paragraph("AI Bug Bounty Scanner Report", ParagraphStyle(
        "title", parent=styles["Title"],
        fontSize=24, textColor=colors.HexColor("#0ea5e9"), spaceAfter=6
    )))
    elements.append(Paragraph("Automated Vulnerability Assessment", ParagraphStyle(
        "subtitle", parent=styles["Normal"],
        fontSize=11, textColor=colors.HexColor("#64748b"), spaceAfter=4
    )))
    elements.append(Spacer(1, 0.2 * inch))

    # ── META ──
    meta_style = ParagraphStyle(
        "meta", parent=styles["Normal"],
        fontSize=11, textColor=colors.HexColor("#1e293b"), spaceAfter=4
    )
    elements.append(Paragraph(f"<b>Target:</b> {safe_pdf_text(target, 100)}", meta_style))
    elements.append(Paragraph(f"<b>Generated:</b> {timestamp}", meta_style))
    elements.append(Spacer(1, 0.15 * inch))

    # ── RISK SCORE BOX ──
    risk_color_map = {
        "#7f1d1d": "#fee2e2",
        "#ef4444": "#fef2f2",
        "#facc15": "#fefce8",
        "#22c55e": "#f0fdf4",
    }
    risk_bg = risk_color_map.get(color, "#f1f5f9")

    risk_data = [[
        Paragraph("<b>Overall Risk Score</b>", ParagraphStyle(
            "rh", parent=styles["Normal"],
            fontSize=12, textColor=colors.HexColor("#1e293b")
        )),
        Paragraph(f"<b>{score}/100 — {label}</b>", ParagraphStyle(
            "rl", parent=styles["Normal"],
            fontSize=14, textColor=colors.HexColor(color)
        ))
    ]]
    risk_table = Table(risk_data, colWidths=[3*inch, 3.5*inch])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(risk_bg)),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(color)),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 0.2 * inch))

    # ── SUMMARY TABLE ──
    high = len([v for v in vulns if v["severity"] in ["HIGH", "CRITICAL"]])
    medium = len([v for v in vulns if v["severity"] == "MEDIUM"])
    low = len([v for v in vulns if v["severity"] == "LOW"])

    summary_data = [
        ["Metric", "Value"],
        ["Total Vulnerabilities", str(len(vulns))],
        ["High / Critical", str(high)],
        ["Medium", str(medium)],
        ["Low", str(low)],
    ]
    summary_table = Table(summary_data, colWidths=[3*inch, 3.5*inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#1e293b")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.HexColor("#f8fafc"),
            colors.HexColor("#e2e8f0")
        ]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3 * inch))

    # ── VULNERABILITY TABLE ──
    elements.append(Paragraph("Vulnerability Details", ParagraphStyle(
        "heading", parent=styles["Heading2"],
        textColor=colors.HexColor("#0ea5e9"), fontSize=14, spaceAfter=8
    )))

    if vulns:
        severity_colors = {
            "CRITICAL": "#7f1d1d",
            "HIGH":     "#dc2626",
            "MEDIUM":   "#d97706",
            "LOW":      "#16a34a",
            "UNKNOWN":  "#64748b",
        }

        # ✅ 5-column table with Next Step
        vuln_data = [["Type", "Severity", "URL", "Payload", "Next Step"]]

        for v in vulns:
            sev = v.get("severity", "").upper()
            sev_color = severity_colors.get(sev, "#64748b")

            # ✅ Get first next step
            suggestions = v.get("suggestions", {})
            next_steps = suggestions.get("next_steps", [])
            first_step = next_steps[0] if next_steps else "Investigate manually"

            vuln_data.append([
                Paragraph(safe_pdf_text(v["type"], 30), ParagraphStyle(
                    "vt", parent=styles["Normal"],
                    fontSize=9, textColor=colors.HexColor("#1e293b")
                )),
                Paragraph(f"<b>{safe_pdf_text(sev, 20)}</b>", ParagraphStyle(
                    "vs", parent=styles["Normal"],
                    fontSize=9, textColor=colors.HexColor(sev_color)
                )),
                Paragraph(safe_pdf_text(v["url"], 50), ParagraphStyle(
                    "vu", parent=styles["Normal"],
                    fontSize=8, textColor=colors.HexColor("#1e293b")
                )),
                Paragraph(safe_pdf_text(v["payload"], 30), ParagraphStyle(
                    "vp", parent=styles["Normal"],
                    fontSize=8, textColor=colors.HexColor("#475569")
                )),
                Paragraph(safe_pdf_text(first_step, 50), ParagraphStyle(
                    "vns", parent=styles["Normal"],
                    fontSize=8, textColor=colors.HexColor("#0ea5e9")
                )),
            ])

        # ✅ 5-column widths
        vuln_table = Table(
            vuln_data,
            colWidths=[1.1*inch, 0.8*inch, 1.8*inch, 1.3*inch, 1.5*inch]
        )
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.HexColor("#f8fafc"),
                colors.HexColor("#e2e8f0")
            ]),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#1e293b")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(vuln_table)

    else:
        elements.append(Paragraph("No vulnerabilities found.", styles["Normal"]))

    # ── FOOTER ──
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(
        "Generated by AI Bug Bounty Scanner — For authorized testing only.",
        ParagraphStyle("footer", parent=styles["Normal"],
                       fontSize=8, textColor=colors.HexColor("#94a3b8"))
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer


# ── DISABLE CACHING ──
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return redirect(url_for("login"))

@app.route("/index")
@login_required
def index():
    return render_template("index.html", username=current_user.username)

@app.route("/dashboard")
@login_required 
def dashboard():
    data = vulnerabilities
    return render_template(
        "dashboard.html",
        total=len(data),
        high=sum(1 for v in data if v["severity"] == "HIGH"),
        medium=sum(1 for v in data if v["severity"] == "MEDIUM"),
        low=sum(1 for v in data if v["severity"] == "LOW")
    )


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    target = request.form.get("target", "").strip()

    # ✅ Server-side validation before starting thread
    from core.validator import validate_target
    is_valid, cleaned_url, error = validate_target(target)

    if not is_valid:
        return render_template("index.html",
                               username=current_user.username,
                               error=error)

    target = cleaned_url
    clear_vulns()
    set_status("starting")
    print(f"[SCAN STARTED] {target}")

    user_id = current_user.id

    def run():
        try:
            set_status("running")
            start_scan(target, user_id=user_id)
            save_scan_history(user_id=user_id)
            set_status("completed")
        except Exception as e:
            print(f"[SCAN ERROR] {e}")
            set_status("error")

    threading.Thread(target=run).start()
    return redirect(url_for("dashboard"))


@app.route("/live_data")
@login_required 
def live_data():
    progress, phase = get_progress()
    score, label, color = get_risk_score()
    return jsonify({
        "total": len(vulnerabilities),
        "high": len([v for v in vulnerabilities if v["severity"] in ["HIGH", "CRITICAL"]]),
        "medium": len([v for v in vulnerabilities if v["severity"] == "MEDIUM"]),
        "low": len([v for v in vulnerabilities if v["severity"] == "LOW"]),
        "vulnerabilities": vulnerabilities,
        "status": get_status(),
        "progress": progress,
        "phase": phase,
        "stats": scan_stats,
        "risk_score": score,
        "risk_label": label,
        "risk_color": color
    })

@app.route("/download_json")
@login_required
def download_json():
    from core.storage import get_risk_score
    import io

    score, label, color = get_risk_score()

    report = {
        "meta": {
            "tool": "AI Bug Bounty Scanner",
            "target": scan_stats["target"],
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_version": "2.0"
        },
        "risk": {
            "score": score,
            "label": label,
            "color": color
        },
        "summary": {
            "total": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v["severity"] == "CRITICAL"]),
            "high": len([v for v in vulnerabilities if v["severity"] == "HIGH"]),
            "medium": len([v for v in vulnerabilities if v["severity"] == "MEDIUM"]),
            "low": len([v for v in vulnerabilities if v["severity"] == "LOW"]),
        },
        "vulnerabilities": list(vulnerabilities)
    }

    buffer = io.BytesIO()
    buffer.write(json.dumps(report, indent=4).encode("utf-8"))
    buffer.seek(0)

    filename = f"report_{scan_stats['target'].replace('http://','').replace('https://','').replace('/','_')}.json"

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/json"
    )

@app.route("/configure_scan", methods=["POST"])
@login_required
def configure_scan():
    target = request.form.get("target", "").strip()

    # ✅ Validate first
    from core.validator import validate_target
    is_valid, cleaned_url, error = validate_target(target)
    if not is_valid:
        return render_template("index.html",
                               username=current_user.username,
                               error=error)

    return render_template("scan_config.html",
                           target=cleaned_url,
                           username=current_user.username)


@app.route("/start_configured_scan", methods=["POST"])
@login_required
def start_configured_scan():
    target = request.form.get("target")
    scan_mode = request.form.get("scan_mode", "standard")
    threads = int(request.form.get("threads", 10))
    delay = float(request.form.get("delay", 0.15))

    # ✅ Which modules are enabled
    config = {
        "headers":   "module_headers"   in request.form,
        "sensitive": "module_sensitive" in request.form,
        "sqli":      "module_sqli"      in request.form,
        "xss":       "module_xss"       in request.form,
        "redirect":  "module_redirect"  in request.form,
        "fuzzer":    "module_fuzzer"    in request.form,
        "login":     "module_login"     in request.form,
        "dirs":      "module_dirs"      in request.form,
        "auth":      "module_auth"      in request.form,  # ✅ NEW
    }

    clear_vulns()
    set_status("starting")
    print(f"[SCAN STARTED] {target} | Mode: {scan_mode} | Threads: {threads}")

    user_id = current_user.id

    def run():
        try:
            set_status("running")
            # ✅ Update rate limiter delay from config
            from modules.rate_limiter import rate_limiter
            rate_limiter.delay = delay

            start_scan(target, user_id=user_id, config=config, threads=threads)
            save_scan_history(user_id=user_id)
            set_status("completed")
        except Exception as e:
            print(f"[SCAN ERROR] {e}")
            set_status("error")

    threading.Thread(target=run).start()
    return redirect(url_for("dashboard"))


@app.route("/report")
@login_required 
def report():
    return render_template("scan_report.html", vulnerabilities=vulnerabilities)


@app.route("/history")
@login_required
def history():
    from auth.database import get_scans_for_user
    scans = get_scans_for_user(current_user.id)  # ✅ only this user's scans
    return render_template("history.html", scans=scans)


@app.route("/download_report")
@login_required 
def download_report():
    score, label, color = get_risk_score()
    buffer = build_pdf(
        target=scan_stats["target"],
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score=score,
        label=label,
        color=color,
        vulns=list(vulnerabilities)
    )
    filename = f"report_{scan_stats['target'].replace('http://','').replace('https://','').replace('/','_')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")


@app.route("/download_history_report/<int:scan_id>")
@login_required
def download_history_report(scan_id):
    from auth.database import get_scan_by_id
    scan = get_scan_by_id(scan_id, current_user.id)  # ✅ user can only access their own

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    buffer = build_pdf(
        target=scan["target"],
        timestamp=scan["timestamp"],
        score=scan.get("risk_score", "N/A"),
        label=scan.get("risk_label", "UNKNOWN"),
        color=scan.get("risk_color", "#94a3b8"),
        vulns=scan.get("vulnerabilities", [])
    )
    filename = f"report_{scan['target'].replace('http://','').replace('https://','').replace('/','_')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")

@app.route("/ai_report")
@login_required
def ai_report():
    from core.storage import get_risk_score
    score, label, color = get_risk_score()

    report = generate_ai_report(
        vulnerabilities=list(vulnerabilities),
        target=scan_stats["target"],
        risk_score=score,
        risk_label=label
    )

    return render_template(
        "ai_report.html",
        report=report,
        target=scan_stats["target"],
        total=len(vulnerabilities),
        score=score,
        label=label
    )


@app.route("/hackerone_report/<int:vuln_index>")
@login_required
def hackerone_report(vuln_index):
    try:
        vuln = list(vulnerabilities)[vuln_index]
    except IndexError:
        return jsonify({"error": "Vulnerability not found"}), 404

    report = generate_hackerone_report(
        vuln=vuln,
        target=scan_stats["target"]
    )

    return jsonify({"report": report})

@app.route('/favicon.ico')
def favicon():
    return "", 204


@app.route('/<path:anything>')
def catch_all(anything):
    print(f"[404 HIT] /{anything}")
    return jsonify({"error": "Not Found"}), 404


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)