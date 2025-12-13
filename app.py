# app.py - full merged application with messaging, reporting, and admin review
# Roles updated: "employer" -> "client", "candidate" -> "contractor"
import os
import math
import re
import sqlite3
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from werkzeug.utils import secure_filename
from flask import send_from_directory, abort


import requests
from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    abort,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash

from models import (
    init_db,
    get_user_by_email,
    create_user,
    get_user_by_id,
    create_job,
    update_job,
    delete_job,
    get_jobs,
    get_job_by_id,
    create_application,
    get_applications_by_job,
    get_applications_by_user,
    get_jobs_by_employer,
    create_rating,
    get_ratings_for_target,
    get_average_rating_for_target,
    get_all_users,
    set_user_ban,
    unset_user_ban,
    delete_user,
    get_rating_by_id,
    delete_rating,
    get_user_by_username,
    set_user_verified,
    update_user_password,
    create_token,
    consume_token,
    purge_expired_tokens,
    get_token_info,
)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "data.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY", "change-me-to-a-random-secret"
)
app.config["DATABASE"] = DB_PATH

# Email / token configuration
app.config["EMAIL_MODE"] = os.environ.get("EMAIL_MODE", "console")  # 'console' or 'smtp'
app.config["MAIL_HOST"] = os.environ.get("MAIL_HOST", "")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587") or 587)
app.config["MAIL_USER"] = os.environ.get("MAIL_USER", "")
app.config["MAIL_PASS"] = os.environ.get("MAIL_PASS", "")
app.config["MAIL_FROM"] = os.environ.get("MAIL_FROM", "no-reply@example.test")

# token expirations (seconds)
app.config["EMAIL_VERIFY_EXPIRATION"] = int(os.environ.get("EMAIL_VERIFY_EXPIRATION", 72 * 3600))
app.config["PASSWORD_RESET_EXPIRATION"] = int(os.environ.get("PASSWORD_RESET_EXPIRATION", 3600))

# Admin secret token used for hidden admin signup/login routes
ADMIN_SECRET_TOKEN = os.environ.get("ADMIN_SECRET_TOKEN", "change-me-admin-secret")

# Initialize DB (creates file + tables if not present)
init_db(app.config["DATABASE"])

# Messaging / reporting tables will be ensured after init_db below

login_manager = LoginManager()
login_manager.login_view = "signin"
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, id, email, role, is_banned=False, banned_until=None, username=None, first_name=None, last_name=None, verified=0):
        self.id = id
        self.email = email
        self.role = role
        self.is_banned = bool(is_banned)
        self.banned_until = banned_until
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.verified = bool(verified)

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    row = get_user_by_id(app.config["DATABASE"], int(user_id))
    if not row:
        return None

    # If get_user_by_id returns a mapping-like (sqlite3.Row), use keys
    try:
        return User(
            id=row["id"],
            email=row["email"],
            role=row.get("role", "contractor"),
            is_banned=row.get("is_banned", False),
            banned_until=row.get("banned_until"),
            username=row.get("username"),
            first_name=row.get("first_name"),
            last_name=row.get("last_name"),
            verified=row.get("verified", 0),
        )
    except Exception:
        # Fallback for tuple-like rows (use the SELECT order from models.get_user_by_id)
        # SELECT id, email, role, is_banned, banned_until, created_at, username, first_name, last_name, verified
        return User(
            id=row[0],
            email=row[1],
            role=row[2],
            is_banned=row[3],
            banned_until=row[4],
            username=row[6],
            first_name=row[7],
            last_name=row[8],
            verified=row[9],
        )


def require_roles(*roles):
    def decorator(fn):
        from functools import wraps

        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("You must sign in to access this page.", "warning")
                return redirect(url_for("signin"))
            # check active ban
            if getattr(current_user, "is_banned", False):
                if current_user.banned_until:
                    try:
                        until = datetime.fromisoformat(current_user.banned_until)
                        if until > datetime.utcnow():
                            flash("Your account is temporarily banned.", "danger")
                            return redirect(url_for("index"))
                    except Exception:
                        flash("Your account is banned.", "danger")
                        return redirect(url_for("index"))
                else:
                    flash("Your account is banned.", "danger")
                    return redirect(url_for("index"))
            if current_user.role not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("index"))
            return fn(*args, **kwargs)

        return wrapped

    return decorator


# --- email helper (console or SMTP) ---
def send_email(subject, recipient, html_body=None, text_body=None):
    mode = app.config.get("EMAIL_MODE", "console")
    if mode == "smtp" and app.config.get("MAIL_HOST"):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = app.config.get("MAIL_FROM")
        msg["To"] = recipient
        if html_body:
            msg.add_alternative(html_body, subtype="html")
            if text_body:
                msg.set_content(text_body)
        else:
            msg.set_content(text_body or subject)
        try:
            server = smtplib.SMTP(app.config.get("MAIL_HOST"), app.config.get("MAIL_PORT"))
            server.starttls()
            if app.config.get("MAIL_USER"):
                server.login(app.config.get("MAIL_USER"), app.config.get("MAIL_PASS"))
            server.send_message(msg)
            server.quit()
            app.logger.info("Sent email to %s via SMTP", recipient)
            return True
        except Exception as e:
            app.logger.exception("Failed to send email via SMTP: %s", e)
            return False
    else:
        # console mode: print link/information to server console (development)
        app.logger.info("EMAIL (console mode) -> To: %s Subject: %s\n\n%s\n\n%s", recipient, subject, text_body or "", html_body or "")
        print("\n--- EMAIL (console mode) ---")
        print("To:", recipient)
        print("Subject:", subject)
        if text_body:
            print(text_body)
        if html_body:
            print(html_body)
        print("--- END EMAIL ---\n")
        return True


# ---- password validator helper ----
def validate_password(password):
    """
    Simple password policy:
      - minimum length 8
      - must include at least one letter and one digit
    Returns (True, None) on success or (False, message) on failure.
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    has_digit = any(c.isdigit() for c in password)
    has_letter = any(c.isalpha() for c in password)
    if not (has_digit and has_letter):
        return False, "Password must contain at least one letter and one number."
    return True, None


# Date formatting filter (MM-DD-YYYY)
@app.template_filter('date_only')
def date_only(value):
    """
    Jinja filter: returns MM-DD-YYYY for ISO-like datetime strings.
    Falls back to several common formats and then the first 10 chars if parsing fails.
    Usage in templates: {{ some_timestamp|date_only }}
    """
    if not value:
        return ""
    # If it's already a datetime object, format directly
    if isinstance(value, datetime):
        return value.strftime("%m-%d-%Y")
    s = str(value).strip()
    # try parsing ISO format (handles 'YYYY-MM-DDTHH:MM:SS[.ffffff]' or 'YYYY-MM-DD HH:MM:SS')
    try:
        dt = datetime.fromisoformat(s)
        return dt.strftime("%m-%d-%Y")
    except Exception:
        pass
    # Try a few common 10-char date formats
    for fmt in ("%Y-%m-%d", "%m-%d-%Y", "%Y/%m/%d", "%m/%d/%Y"):
        try:
            dt = datetime.strptime(s[:10], fmt)
            return dt.strftime("%m-%d-%Y")
        except Exception:
            continue
    # Fallback: return first 10 characters (best-effort)
    return s[:10]

@app.template_filter('datetime_format')
def datetime_format(value):
    """
    Format datetime for display in conversation view.
    """
    if not value:
        return ""
    try:
        # Try to parse the datetime
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        else:
            dt = value
        
        # Format as: Jan 15, 2024 2:30 PM
        return dt.strftime("%b %d, %Y %I:%M %p")
    except Exception:
        # Fallback to original value
        return str(value)

@app.context_processor
def inject_current_year():
    return {"current_year": datetime.utcnow().year}

@app.context_processor
def inject_has_edit_profile():
    # Template-safe way to detect whether the edit_profile endpoint exists.
    # Avoids calling url_for inside templates which raises BuildError if the endpoint is missing.
    try:
        return {"has_edit_profile": "edit_profile" in app.view_functions}
    except Exception:
        return {"has_edit_profile": False}

# safe_url_for helper for templates (defensive - prevents BuildError from bubbling to template)
@app.context_processor
def utility_processor():
    def safe_url_for(endpoint, **values):
        try:
            return url_for(endpoint, **values)
        except Exception:
            return "#"
    return {"safe_url_for": safe_url_for}

# Template global to display human-friendly role names in templates
@app.template_global()
def role_display(role):
    """
    Return a human-friendly display string for a role.
    Examples:
      'admin' -> 'Administrator'
      'client' -> 'Client'
      'contractor' -> 'Contractor'
    Falls back to capitalized raw role or 'N/A'.
    """
    try:
        mapping = {
            "admin": "Administrator",
            "client": "Client",
            "contractor": "Contractor",
        }
        if role is None:
            return "N/A"
        # Normalize and look up mapping
        key = str(role).strip().lower()
        return mapping.get(key, key.capitalize())
    except Exception:
        return "N/A"

# --- Geocoding helper (uses free OpenStreetMap Nominatim) ---
def geocode_address(address):
    """
    Geocode an address using Nominatim (OpenStreetMap).
    Returns (lat: float, lon: float, display_name: str) or (None, None, None) on failure.
    This uses the free Nominatim service — be mindful of rate limits for heavy usage.
    """
    if not address:
        return None, None, None
    url = "https://nominatim.openstreetmap.org/search"
    params = {"q": address, "format": "json", "limit": 1}
    headers = {"User-Agent": "GetAJob/1.0 (dev@localhost)"}  # please replace contact for production
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=8)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) and len(data) > 0:
            item = data[0]
            lat = float(item.get("lat"))
            lon = float(item.get("lon"))
            name = item.get("display_name")
            return lat, lon, name
    except Exception as e:
        app.logger.warning("Geocode failed for %r: %s", address, e)
    return None, None, None


@app.route("/")
def index():
    # If user is signed in, send them to their landing page based on role.
    # Otherwise render the public (unsigned) homepage.
    if current_user.is_authenticated:
        role = getattr(current_user, "role", None)
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        if role == "client":
            return redirect(url_for("client_dashboard"))
        # default signed-in landing for non-admin, non-client roles:
        # treat as contractor landing page
        return redirect(url_for("contractor_dashboard"))
    return render_template("index.html")


#
# Auth routes (including secret admin signup/login)
#
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        # role default changed: candidate -> contractor
        role = request.form.get("role", "contractor")
        username = request.form.get("username", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()

        if not email or not password or not username:
            flash("Email, username and password are required.", "danger")
            return render_template("signup.html", email=email, role=role, username=username, first_name=first_name, last_name=last_name)

        # username basic validation
        if not re.match(r"^[A-Za-z0-9_.-]{3,30}$", username):
            flash("Username must be 3-30 characters and contain only letters, numbers, ., -, or _", "danger")
            return render_template("signup.html", email=email, role=role, username=username, first_name=first_name, last_name=last_name)

        # password policy
        ok, reason = validate_password(password)
        if not ok:
            flash(reason, "danger")
            return render_template("signup.html", email=email, role=role, username=username, first_name=first_name, last_name=last_name)

        existing = get_user_by_email(app.config["DATABASE"], email)
        if existing:
            flash("An account with that email already exists.", "warning")
            return render_template("signup.html", email=email, role=role, username=username, first_name=first_name, last_name=last_name)

        # username uniqueness check
        if get_user_by_username(app.config["DATABASE"], username):
            flash("Username already taken; please choose another.", "warning")
            return render_template("signup.html", email=email, role=role, username=username, first_name=first_name, last_name=last_name)

        password_hash = generate_password_hash(password)
        try:
            user = create_user(
                app.config["DATABASE"],
                email,
                password_hash,
                role=role,
                username=username,
                first_name=first_name or None,
                last_name=last_name or None,
                verified=0,
            )
        except sqlite3.IntegrityError:
            flash("An account with that email or username already exists.", "warning")
            return render_template("signup.html", email=email, role=role, username=username, first_name=first_name, last_name=last_name)

        # send verification email using DB-backed token
        token = create_token(app.config["DATABASE"], email, purpose="verify", expires_seconds=app.config.get("EMAIL_VERIFY_EXPIRATION", 72 * 3600))
        verify_url = url_for("verify_email", token=token, _external=True)
        text = f"Hi {first_name or username},\n\nPlease verify your email by clicking the link below:\n\n{verify_url}\n\nIf you did not sign up, ignore this message.\n"
        html = f"<p>Hi {first_name or username},</p><p>Please verify your email by clicking <a href='{verify_url}'>this link</a>.</p>"
        send_email("Verify your Jobsite account", email, html_body=html, text_body=text)
        flash("Signup successful. A verification email has been sent. Please verify your email before signing in.", "success")
        return redirect(url_for("signin"))

    return render_template("signup.html")

@app.route("/contractor/dashboard")
@require_roles("contractor")
def contractor_dashboard():
    """
    Show a contractor their applications and the corresponding job summary.
    """
    try:
        user_id = int(current_user.get_id())
        apps = get_applications_by_user(app.config["DATABASE"], user_id)
        # Build enriched list of entries with job and employer info
        applications = []
        for a in apps:
            job = get_job_by_id(app.config["DATABASE"], a["job_id"])
            employer = None
            if job:
                employer = get_user_by_id(app.config["DATABASE"], job.get("employer_id"))
            applications.append({"application": a, "job": job, "employer": employer})
        return render_template("contractor_dashboard.html", applications=applications)
    except Exception:
        app.logger.exception("Failed to load contractor dashboard")
        flash("Unable to load your dashboard right now.", "danger")
        return redirect(url_for("index"))

@app.route(f"/admin/{ADMIN_SECRET_TOKEN}/signup", methods=["GET", "POST"])
def admin_signup_secret():
    # Hidden signup path to create admin accounts
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and password required.", "danger")
            return render_template("admin_signup.html")

        ok, reason = validate_password(password)
        if not ok:
            flash(reason, "danger")
            return render_template("admin_signup.html")

        existing = get_user_by_email(app.config["DATABASE"], email)
        if existing:
            flash("Account exists.", "warning")
            return render_template("admin_signup.html")
        password_hash = generate_password_hash(password)
        try:
            user = create_user(app.config["DATABASE"], email, password_hash, role="admin", verified=1)
        except sqlite3.IntegrityError:
            flash("Account with that email already exists.", "warning")
            return render_template("admin_signup.html")
        user_obj = User(id=user["id"], email=user["email"], role="admin", verified=user.get("verified", 0))
        login_user(user_obj)
        flash("Admin account created and signed in.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_signup.html")

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template("signin.html", email=email)

        user_row = get_user_by_email(app.config["DATABASE"], email)
        if not user_row:
            flash("Invalid credentials.", "danger")
            return render_template("signin.html", email=email)

        # Check if banned
        if user_row.get("is_banned"):
            banned_until = user_row.get("banned_until")
            if banned_until:
                try:
                    until = datetime.fromisoformat(banned_until)
                    if until > datetime.utcnow():
                        flash("Your account is temporarily banned until %s" % banned_until, "danger")
                        return render_template("signin.html", email=email)
                except Exception:
                    flash("Your account is banned.", "danger")
                    return render_template("signin.html", email=email)
            else:
                flash("Your account is banned.", "danger")
                return render_template("signin.html", email=email)

        if not check_password_hash(user_row["password_hash"], password):
            flash("Invalid credentials.", "danger")
            return render_template("signin.html", email=email)

        # Check verified
        if not user_row.get("verified"):
            flash("Please verify your email before signing in. Check your email for the verification link.", "warning")
            return render_template("signin.html", email=email)

        user_obj = User(
            id=user_row["id"],
            email=user_row["email"],
            role=user_row.get("role", "contractor"),  # default contractor
            is_banned=user_row.get("is_banned", 0),
            banned_until=user_row.get("banned_until"),
            username=user_row.get("username"),
            first_name=user_row.get("first_name"),
            last_name=user_row.get("last_name"),
            verified=user_row.get("verified", 0),
        )
        login_user(user_obj)
        flash("Signed in successfully.", "success")
        return redirect(url_for("profile"))

    return render_template("signin.html")

@app.route("/admin/conversation/view")
@require_roles("admin")
def admin_conversation_view():
    """
    Admin view to see a conversation between two users.
    """
    user_a_id = request.args.get('user_a_id')
    user_b_id = request.args.get('user_b_id')
    report_id = request.args.get('report_id')
    
    if not user_a_id or not user_b_id:
        flash("Missing user IDs", "danger")
        return redirect(url_for('admin_reports_page'))
    
    try:
        user_a_id = int(user_a_id)
        user_b_id = int(user_b_id)
    except ValueError:
        flash("Invalid user IDs", "danger")
        return redirect(url_for('admin_reports_page'))
    
    # Get users
    user_a = get_user_by_id(app.config["DATABASE"], user_a_id)
    user_b = get_user_by_id(app.config["DATABASE"], user_b_id)
    
    # Get conversation messages
    messages = get_conversation_rows(app.config["DATABASE"], user_a_id, user_b_id)
    
    # Get report info if report_id is provided
    report_info = None
    if report_id:
        try:
            report_info = get_report_by_id(app.config["DATABASE"], int(report_id))
            if report_info:
                # Add user objects to report info
                report_info["reporter"] = get_user_by_id(app.config["DATABASE"], report_info["reporter_id"])
        except Exception:
            pass
    
    return render_template(
        "conversation_view.html",
        user_a=user_a,
        user_b=user_b,
        user_a_id=user_a_id,
        user_b_id=user_b_id,
        messages=messages,
        report_info=report_info
    )
@app.route("/admin/conversation/delete", methods=["POST"])
@require_roles("admin")
def admin_delete_conversation():
    """
    Delete a conversation between two users.
    """
    user_a_id = request.form.get('user_a_id')
    user_b_id = request.form.get('user_b_id')
    
    if not user_a_id or not user_b_id:
        flash("Missing user IDs", "danger")
        return redirect(url_for('admin_reports_page'))
    
    try:
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.execute(
            "DELETE FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)",
            (int(user_a_id), int(user_b_id), int(user_b_id), int(user_a_id))
        )
        conn.commit()
        conn.close()
        
        flash("Conversation deleted successfully", "success")
    except Exception as e:
        app.logger.exception("Failed to delete conversation")
        flash("Failed to delete conversation", "danger")
    
    return redirect(url_for('admin_reports_page'))

@app.route("/rate/user/<int:user_id>", methods=["POST"])
@login_required
def rate_user(user_id):
    # Prevent users rating themselves
    try:
        current_id = int(current_user.get_id())
    except Exception:
        flash("Invalid user.", "danger")
        return redirect(url_for("index"))

    if current_id == user_id:
        flash("You cannot rate yourself.", "warning")
        return redirect(url_for("profile", user_id=user_id))

    # Validate target exists
    row = get_user_by_id(app.config["DATABASE"], user_id)
    if not row:
        flash("User not found.", "warning")
        return redirect(url_for("index"))

    # Parse rating
    try:
        rating = int(request.form.get("rating", 0))
    except Exception:
        rating = 0

    if rating < 1 or rating > 5:
        flash("Rating must be between 1 and 5.", "danger")
        return redirect(url_for("profile", user_id=user_id))

    comment = (request.form.get("comment") or "").strip() or None

    # create_rating(db_path, target_type, target_id, rater_id, rating, comment=None)
    try:
        create_rating(app.config["DATABASE"], "user", user_id, current_id, rating, comment)
        flash("Rating submitted.", "success")
    except Exception as e:
        # Defensive: report an error if DB insert fails
        flash("Unable to save rating.", "danger")

    return redirect(url_for("profile", user_id=user_id))

@app.route("/resend-verify", methods=["POST"])
def resend_verify():
    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("Email required.", "danger")
        return redirect(url_for("signin"))
    user_row = get_user_by_email(app.config["DATABASE"], email)
    if not user_row:
        flash("No account found with that email.", "warning")
        return redirect(url_for("signin"))
    if user_row.get("verified"):
        flash("Account already verified. Please sign in.", "info")
        return redirect(url_for("signin"))
    token = create_token(app.config["DATABASE"], email, purpose="verify", expires_seconds=app.config.get("EMAIL_VERIFY_EXPIRATION", 72 * 3600))
    verify_url = url_for("verify_email", token=token, _external=True)
    text = f"Please verify your email by visiting: {verify_url}"
    html = f"<p>Please verify your email by clicking <a href='{verify_url}'>this link</a>.</p>"
    send_email("Verify your Jobsite account", email, html_body=html, text_body=text)
    flash("Verification email resent. Check your inbox.", "success")
    return redirect(url_for("signin"))


@app.route("/verify-email/<token>")
def verify_email(token):
    email = consume_token(app.config["DATABASE"], token, purpose="verify")
    if not email:
        flash("Verification link is invalid or has expired.", "danger")
        return redirect(url_for("signin"))
    # mark verified
    ok = set_user_verified(app.config["DATABASE"], email)
    if ok:
        flash("Email verified. You may now sign in.", "success")
    else:
        flash("Unable to verify email. Contact admin.", "danger")
    return redirect(url_for("signin"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Email is required.", "danger")
            return render_template("forgot_password.html")
        user_row = get_user_by_email(app.config["DATABASE"], email)
        if not user_row:
            # don't reveal account existence
            flash("If that email exists, a password reset link has been sent.", "info")
            return redirect(url_for("signin"))
        token = create_token(app.config["DATABASE"], email, purpose="reset", expires_seconds=app.config.get("PASSWORD_RESET_EXPIRATION", 3600))
        reset_url = url_for("reset_password", token=token, _external=True)
        text = f"To reset your password, visit: {reset_url}\nIf you did not request this, ignore this message."
        html = f"<p>To reset your password, click <a href='{reset_url}'>this link</a>.</p>"
        send_email("Jobsite password reset", email, html_body=html, text_body=text)
        flash("If that email exists, a password reset link has been sent.", "info")
        return redirect(url_for("signin"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # GET: validate token without consuming so user can see the form.
    if request.method == "GET":
        info = get_token_info(app.config["DATABASE"], token, purpose="reset")
        if not info:
            flash("Password reset link is invalid or has expired.", "danger")
            return redirect(url_for("forgot_password"))
        return render_template("reset_password.html", token=token)

    # POST: consume the token (one-time) and update password
    email = consume_token(app.config["DATABASE"], token, purpose="reset")
    if not email:
        flash("Password reset link is invalid or has expired.", "danger")
        return redirect(url_for("forgot_password"))

    password = request.form.get("password", "")
    ok, reason = validate_password(password)
    if not ok:
        flash(reason, "danger")
        return render_template("reset_password.html", token=token)

    password_hash = generate_password_hash(password)
    update_user_password(app.config["DATABASE"], email, password_hash)
    flash("Password has been reset. You may sign in now.", "success")
    return redirect(url_for("signin"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("index"))

# Add this function to your app.py (somewhere near the other database functions)

def update_report_status(db_path, report_id, status):
    """
    Update the status of a report.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE message_reports SET status = ? WHERE id = ?",
            (status, int(report_id))
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

# Add this download route to serve uploaded PDFs.
from flask import send_from_directory, abort
import os

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    """
    Serve uploaded PDF files saved in UPLOAD_DIR.
    - Only one uploaded_file route must exist.
    - filename should be the saved filename (not a path). Templates should pass basename.
    - Returns 404 if file missing.
    """
    # Security: only use basename to avoid path traversal
    safe_name = os.path.basename(filename)
    full_path = os.path.join(UPLOAD_DIR, safe_name)
    if not os.path.isfile(full_path):
        abort(404)
    return send_from_directory(UPLOAD_DIR, safe_name, as_attachment=False)

# Replace existing /apply/<job_id> and /uploads/<filename> routes with these implementations.

def _save_uploaded(f):
    """
    Save uploaded file to UPLOAD_DIR and return the saved filename (not a path).
    Returns None if file invalid or save failed.
    """
    if not f or f.filename == "":
        return None
    filename = secure_filename(f.filename)
    base, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext != ".pdf":
        return None
    # extra mime check if provided
    if f.content_type and not any(m in f.content_type for m in ALLOWED_MIMES):
        return None
    # unique filename
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    try:
        uid = int(current_user.get_id())
    except Exception:
        uid = "anon"
    filename_unique = f"{ts}_u{uid}_{base}{ext}"
    dest_path = os.path.join(UPLOAD_DIR, filename_unique)
    try:
        f.save(dest_path)
    except Exception as e:
        app.logger.exception("Failed to save uploaded file: %s", e)
        return None
    return filename_unique

@app.route("/apply/<int:job_id>", methods=["POST"])
@login_required
def apply_job(job_id):
    # Ensure current_user id is valid
    try:
        current_id = int(current_user.get_id())
    except Exception:
        flash("Invalid user.", "danger")
        return redirect(url_for("index"))

    # Enforce role == contractor
    role = getattr(current_user, "role", None)
    if role is None:
        try:
            role = current_user.role
        except Exception:
            role = None
    if str(role).lower() != "contractor":
        flash("Only contractors can apply for jobs.", "warning")
        return redirect(url_for("job_detail", job_id=job_id))

    # Ensure job exists
    job = get_job_by_id(app.config["DATABASE"], job_id)
    if not job:
        flash("Job not found.", "warning")
        return redirect(url_for("jobs_list"))

    # Prevent applying to your own job
    try:
        employer_id = int(job.get("employer_id") if isinstance(job, dict) else job.employer_id)
    except Exception:
        employer_id = job.get("employer_id") if isinstance(job, dict) else getattr(job, "employer_id", None)
    if employer_id is not None and int(employer_id) == current_id:
        flash("You cannot apply to your own job.", "warning")
        return redirect(url_for("job_detail", job_id=job_id))

    # Prevent duplicate applications
    try:
        apps = get_applications_by_job(app.config["DATABASE"], job_id) or []
    except Exception:
        apps = []
    for a in apps:
        try:
            if int(a.get("user_id") or a["user_id"]) == current_id:
                flash("You have already applied for this job.", "info")
                return redirect(url_for("job_detail", job_id=job_id))
        except Exception:
            continue

    # Save uploaded files (uses _save_uploaded helper which should be defined once)
    cover_file = request.files.get("cover_letter_file")
    resume_file = request.files.get("resume_file")

    cover_letter_filename = None
    resume_filename = None

    try:
        cover_letter_filename = _save_uploaded(cover_file)
    except Exception:
        cover_letter_filename = None

    try:
        resume_filename = _save_uploaded(resume_file)
    except Exception:
        resume_filename = None

    # Legacy textual fields (still accepted)
    cover_letter_text = (request.form.get("cover_letter") or "").strip() or None
    resume_text = (request.form.get("resume_text") or "").strip() or None

    # Save application to DB (store filenames). Be defensive about model signatures.
    app_record = None
    app_id = None
    try:
        # Preferred: model supports storing file paths
        app_record = create_application(
            app.config["DATABASE"],
            job_id,
            current_id,
            cover_letter=cover_letter_text,
            resume_text=resume_text,
            cover_letter_path=cover_letter_filename,
            resume_path=resume_filename,
        )
        # create_application is expected to return a dict with id, but handle other shapes defensively
        if isinstance(app_record, dict):
            app_id = app_record.get("id") or app_record.get("app_id") or app_record.get("application_id")
    except TypeError:
        # model likely has older signature without file path args; fall back
        try:
            app_record = create_application(app.config["DATABASE"], job_id, current_id, cover_letter_text, resume_text)
            if isinstance(app_record, dict):
                app_id = app_record.get("id") or app_record.get("app_id") or app_record.get("application_id")
        except Exception:
            flash("Unable to save your application. Please try again.", "danger")
            return redirect(url_for("job_detail", job_id=job_id))
    except Exception:
        # any other error while creating the application
        try:
            app_record = create_application(app.config["DATABASE"], job_id, current_id, cover_letter_text, resume_text)
            if isinstance(app_record, dict):
                app_id = app_record.get("id") or app_record.get("app_id") or app_record.get("application_id")
        except Exception:
            flash("Unable to save your application. Please try again.", "danger")
            return redirect(url_for("job_detail", job_id=job_id))

    # If create_application didn't already persist file-path columns but the DB supports them,
    # update the new application row with the stored filenames.
    if app_id and (cover_letter_filename or resume_filename):
        try:
            import sqlite3

            db_path = app.config["DATABASE"]
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            # find columns on the applications table
            cur.execute("PRAGMA table_info(applications)")
            cols = [r[1] for r in cur.fetchall()]  # column name is at index 1

            updates = []
            params = []
            if "cover_letter_path" in cols and cover_letter_filename:
                updates.append("cover_letter_path = ?")
                params.append(cover_letter_filename)
            if "resume_path" in cols and resume_filename:
                updates.append("resume_path = ?")
                params.append(resume_filename)

            if updates:
                params.append(app_id)
                sql = "UPDATE applications SET " + ", ".join(updates) + " WHERE id = ?"
                cur.execute(sql, params)
                conn.commit()

            conn.close()
        except Exception:
            # Non-fatal — if this fails we still continue (files may still be inaccessible
            # if DB/schema doesn't match; handle that separately by migrating schema).
            app.logger.exception("Failed to persist uploaded filenames for application %s", app_id)

    # Notify employer (best-effort)
    try:
        employer = get_user_by_id(app.config["DATABASE"], int(employer_id))
        if employer and employer.get("email"):
            subject = f"New application for: {job.get('title') or getattr(job, 'title', '')}"
            applicant_name = getattr(current_user, "username", None) or getattr(current_user, "first_name", "") or getattr(current_user, "email", "")
            job_url = url_for("job_detail", job_id=job_id, _external=True)
            text_body = f"{applicant_name} has applied for your job '{job.get('title') or getattr(job, 'title', '')}'.\n\nView job: {job_url}"
            html_body = f"<p><strong>{applicant_name}</strong> has applied for your job '<em>{job.get('title') or getattr(job, 'title', '')}</em>'.</p><p><a href='{job_url}'>View job</a></p>"
            send_email("New application on Jobsite", employer.get("email"), html_body=html_body, text_body=text_body)
    except Exception:
        pass

    flash("Application submitted. It will appear on your applications page.", "success")
    try:
        return redirect(url_for("contractor_dashboard"))
    except Exception:
        try:
            return redirect(url_for("profile"))
        except Exception:
            return redirect(url_for("job_detail", job_id=job_id))

@app.context_processor
def inject_tile_settings():
    """
    Provide TILE_URL and TILE_ATTRIBUTION for the map template.
    - If MAPTILER_KEY is present in env/app.config, use MapTiler (recommended).
    - Otherwise fall back to the public OSM tiles (rate-limited).
    """
    key = os.environ.get("MAPTILER_KEY") or app.config.get("MAPTILER_KEY")
    if key:
        # MapTiler example (requires free account / key)
        tile_url = f"https://api.maptiler.com/maps/streets/{{z}}/{{x}}/{{y}}.png?key={key}"
        tile_attr = '© MapTiler © OpenStreetMap contributors'
    else:
        # Public OSM tiles (subject to usage policy / rate limits)
        tile_url = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        tile_attr = '&copy; OpenStreetMap contributors'
    return {"TILE_URL": tile_url, "TILE_ATTRIBUTION": tile_attr}

# Profile view: allow public access to view any user's profile and show ratings.
# Also keep existing behavior for viewing your own profile when signed in.
@app.route("/profile")
@app.route("/profile/<int:user_id>")
def profile(user_id=None):
    """
    Render a user's profile page.
    - If user_id is provided, show that user's profile (public).
    - If not provided, require authentication and show current user's profile.
    - Collect ratings for the target user and compute an average for display.
    """
    db_path = app.config.get("DATABASE")

    # Determine which user to display
    if user_id is None:
        # show current user's profile (must be signed in)
        if not current_user.is_authenticated:
            flash("Please sign in to view your profile.", "warning")
            return redirect(url_for("signin"))
        try:
            target_id = int(current_user.get_id())
        except Exception:
            flash("Invalid user.", "danger")
            return redirect(url_for("index"))
    else:
        target_id = int(user_id)

    # Load the target user
    user_row = get_user_by_id(db_path, target_id)
    if not user_row:
        abort(404)

    # Load ratings for this user (non-fatal if it fails)
    ratings = []
    avg_rating = None
    try:
        rows = get_ratings_for_target(db_path, "user", target_id) or []
        total = 0
        count = 0
        for r in rows:
            # normalize rating value
            try:
                r_rating = int(r.get("rating") if isinstance(r, dict) else r.rating)
            except Exception:
                continue
            total += r_rating
            count += 1

            # attach rater email for display if possible (best-effort)
            rater_id = r.get("rater_id") if isinstance(r, dict) else getattr(r, "rater_id", None)
            rater_email = None
            try:
                if rater_id:
                    rr = get_user_by_id(db_path, int(rater_id))
                    if rr:
                        rater_email = rr.get("email") if isinstance(rr, dict) else getattr(rr, "email", None)
            except Exception:
                rater_email = None

            # ensure template can access these keys
            if isinstance(r, dict):
                r["rater_email"] = rater_email
            else:
                # if r is an object-like row, try to set attribute (best-effort)
                try:
                    setattr(r, "rater_email", rater_email)
                except Exception:
                    pass

            ratings.append(r)

        if count > 0:
            avg_rating = float(total) / float(count)
    except Exception:
        # ignore rating loading errors but log
        app.logger.exception("Failed to load ratings for user %s", target_id)
        ratings = []
        avg_rating = None

    # Render the profile template (template already contains logic to show rating form only when
    # current_user is authenticated and viewing another user's profile)
    return render_template("profile.html", user=user_row, avg_rating=avg_rating, ratings=ratings)


#
# Jobs listing + filtering
#
def haversine_miles(lat1, lon1, lat2, lon2):
    # returns distance in miles between two points
    R = 3958.8  # Earth radius in miles
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

@app.route("/job/<int:job_id>/applicants")
@login_required
def job_applicants(job_id):
    """
    Owner-only view: list all applications for a given job, including uploaded files and applicant email.
    """
    # current user id
    try:
        current_id = int(current_user.get_id())
    except Exception:
        flash("Invalid user.", "danger")
        return redirect(url_for("index"))

    # Load job
    job = get_job_by_id(app.config["DATABASE"], job_id)
    if not job:
        flash("Job not found.", "warning")
        return redirect(url_for("jobs_list"))

    # Determine job owner id robustly
    employer_id = job.get("employer_id") if isinstance(job, dict) else getattr(job, "employer_id", None)
    try:
        employer_id = int(employer_id) if employer_id is not None else None
    except Exception:
        employer_id = None

    # Authorize: only employer (owner) or admin can view
    user_role = getattr(current_user, "role", None) or ""
    if employer_id != current_id and str(user_role).lower() != "admin":
        flash("You are not authorized to view applicants for this job.", "warning")
        return redirect(url_for("job_detail", job_id=job_id))

    # Load applications (get_applications_by_job returns rows that include applicant_email, cover_letter_path, resume_path)
    applications = get_applications_by_job(app.config["DATABASE"], job_id) or []

    return render_template("job_applicants.html", job=job, applications=applications)

@app.route("/jobs")
@login_required
def jobs_list():
    q = (request.args.get("q") or "").strip().lower()
    tags_q = (request.args.get("tags") or "").strip().lower()
    remote_only = request.args.get("remote", "").lower() in ("1", "true", "yes", "on")
    page = max(int(request.args.get("page", 1)), 1)
    per_page = max(min(int(request.args.get("per_page", 20)), 100), 1)
    sort = (request.args.get("sort") or "date").lower()

    lat = request.args.get("lat")
    lng = request.args.get("lng")
    center_lat = None
    center_lng = None
    try:
        if lat is not None and lng is not None and lat != "" and lng != "":
            center_lat = float(lat)
            center_lng = float(lng)
    except ValueError:
        center_lat = center_lng = None

    try:
        radius_miles = float(request.args.get("radius_miles", 0)) if request.args.get("radius_miles") else None
    except ValueError:
        radius_miles = None

    all_jobs = get_jobs(app.config["DATABASE"])
    filtered = []
    for j in all_jobs:
        include = True
        if q:
            in_title = q in (j.get("title") or "").lower()
            in_descr = q in (j.get("description") or "").lower()
            in_tags = q in (j.get("tags") or "").lower() if j.get("tags") else False
            include = in_title or in_descr or in_tags
        if not include:
            continue

        if tags_q:
            wanted = [t.strip() for t in tags_q.split(",") if t.strip()]
            job_tags = (j.get("tags") or "").lower()
            if not any(w in job_tags.split(",") or w in job_tags for w in wanted):
                continue

        if remote_only:
            job_tags = (j.get("tags") or "").lower()
            if "remote" not in job_tags:
                continue

        jlat = j.get("lat")
        jlng = j.get("lng")
        if center_lat is not None and jlat is not None and jlng is not None and jlat != "" and jlng != "":
            try:
                jlat_f = float(jlat)
                jlng_f = float(jlng)
                dist = haversine_miles(center_lat, center_lng, jlat_f, jlng_f)
                j["_distance_miles"] = round(dist, 2)
                if radius_miles is not None and dist > radius_miles:
                    continue
            except Exception:
                j["_distance_miles"] = None
        else:
            j["_distance_miles"] = None

        filtered.append(j)

    if sort == "distance" and center_lat is not None:
        filtered.sort(key=lambda x: (x.get("_distance_miles") is None, x.get("_distance_miles") or 99999))
    else:
        filtered.sort(key=lambda x: x.get("created_at") or "", reverse=True)

    total = len(filtered)
    start = (page - 1) * per_page
    end = start + per_page
    page_jobs = filtered[start:end]

    query_args = dict(request.args)
    query_args.pop("page", None)

    return render_template(
        "jobs_list.html",
        jobs=page_jobs,
        total=total,
        page=page,
        per_page=per_page,
        q=request.args.get("q", ""),
        tags=request.args.get("tags", ""),
        remote=remote_only,
        lat=center_lat,
        lng=center_lng,
        radius_miles=radius_miles,
        sort=sort,
        query_args=query_args,
    )


# Add client location, map, API endpoints (map and job APIs)
@app.route("/_client_location")
def client_location():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()
    if ip in ("127.0.0.1", "::1", "localhost"):
        return jsonify(ok=False)
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        resp.raise_for_status()
        j = resp.json()
        lat = j.get("latitude") or j.get("lat")
        lon = j.get("longitude") or j.get("lon")
        city = j.get("city")
        region = j.get("region")
        if lat is None or lon is None:
            return jsonify(ok=False)
        return jsonify(ok=True, lat=float(lat), lon=float(lon), city=city, region=region)
    except Exception as e:
        app.logger.debug("Client location lookup failed for ip %s: %s", ip, e)
        return jsonify(ok=False)

UPLOAD_SUBDIR = "uploads"
UPLOAD_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static", UPLOAD_SUBDIR)
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf"}
ALLOWED_MIMES = {"application/pdf"}

def _allowed_file(filename, content_type):
    """
    Basic check: allow only .pdf extension and (if provided) PDF mime-type.
    Returns True if allowed, False otherwise.
    """
    if not filename:
        return False
    ext = os.path.splitext(filename)[1].lstrip(".").lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    if content_type:
        # some clients may provide 'application/pdf; charset=binary' so use 'in'
        if not any(m in content_type for m in ALLOWED_MIMES):
            return False
    return True


@app.route("/map")
@login_required
def map_view():
    return render_template("map.html")


# -- Short address helpers --
US_STATES = {
    "alabama":"AL","alaska":"AK","arizona":"AZ","arkansas":"AR","california":"CA","colorado":"CO",
    "connecticut":"CT","delaware":"DE","florida":"FL","georgia":"GA","hawaii":"HI","idaho":"ID",
    "illinois":"IL","indiana":"IN","iowa":"IA","kansas":"KS","kentucky":"KY","louisiana":"LA",
    "maine":"ME","maryland":"MD","massachusetts":"MA","michigan":"MI","minnesota":"MN","mississippi":"MS",
    "missouri":"MO","montana":"MT","nebraska":"NE","nevada":"NV","new hampshire":"NH","new jersey":"NJ",
    "new mexico":"NM","new york":"NY","north carolina":"NC","north dakota":"ND","ohio":"OH",
    "oklahoma":"OK","oregon":"OR","pennsylvania":"PA","rhode island":"RI","south carolina":"SC",
    "south dakota":"SD","tennessee":"TN","texas":"TX","utah":"UT","vermont":"VT","virginia":"VA",
    "washington":"WA","west virginia":"WV","wisconsin":"WI","wyoming":"WY","district of columbia":"DC"
}
def create_simple_warning(db_path, user_id, message):
    """
    Create a simple warning for a user.
    """
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO user_warnings (user_id, message, created_at) VALUES (?, ?, ?)",
            (int(user_id), message, now)
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

def get_user_warnings(db_path, user_id):
    """
    Get warnings for a user.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM user_warnings WHERE user_id = ?",
            (int(user_id),)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def _lookup_us_state_abbrev(name):
    if not name:
        return None
    n = name.strip().lower()
    if len(n) == 2 and n.upper() in US_STATES.values():
        return n.upper()
    if n in US_STATES:
        return US_STATES[n]
    return None

def short_addr_from_display(display_name):
    if not display_name:
        return ""
    parts = [p.strip() for p in display_name.split(",") if p.strip()]
    if not parts:
        return ""
    street = parts[0]
    city = None
    state = None
    if len(parts) >= 2:
        city = parts[1]
    candidates = []
    if len(parts) >= 3:
        candidates.extend(parts[2:5])
    else:
        candidates.extend(parts[1:])
    for c in candidates:
        if not c:
            continue
        if c.replace(" ", "").isdigit():
            continue
        abbrev = _lookup_us_state_abbrev(c)
        if abbrev:
            state = abbrev
            break
        first_tok = c.split()[0]
        abbrev = _lookup_us_state_abbrev(first_tok)
        if abbrev:
            state = abbrev
            break
    if state is None:
        if len(parts) >= 3:
            region = parts[2]
            if region and region.lower() != parts[-1].lower():
                state = region
            else:
                state = parts[-2] if len(parts) >= 2 else None
        else:
            state = None
    out_parts = []
    if street:
        out_parts.append(street)
    city_state = []
    if city:
        city_state.append(city)
    if state:
        city_state.append(state)
    if city_state:
        out_parts.append(", ".join(city_state))
    return ", ".join(out_parts)

@app.template_filter('short_addr')
def short_addr_filter(value):
    try:
        return short_addr_from_display(value) or ""
    except Exception:
        return (value or "")


@app.route("/api/jobs")
@login_required
def api_jobs():
    try:
        rows = get_jobs(app.config["DATABASE"])
        jobs = []
        for r in rows:
            lat_val = float(r["lat"]) if r.get("lat") not in (None, "") else None
            lng_val = float(r["lng"]) if r.get("lng") not in (None, "") else None
            loc_text = r.get("location_text")
            jobs.append({
                "id": r["id"],
                "employer_id": r["employer_id"],
                "title": r["title"],
                "description": r["description"],
                "location_text": loc_text,
                "short_location": short_addr_from_display(loc_text),
                "lat": lat_val,
                "lng": lng_val,
                "salary": r.get("salary"),
                "tags": r.get("tags"),
                "created_at": r.get("created_at"),
            })
        return jsonify({"ok": True, "jobs": jobs})
    except Exception:
        app.logger.exception("API /api/jobs failed")
        return jsonify({"ok": False, "error": "Internal server error"}), 500

@app.route("/api/jobs_nearby")
@login_required
def api_jobs_nearby():
    try:
        lat = request.args.get("lat")
        lng = request.args.get("lng")
        radius_miles = request.args.get("radius_miles")
        center_lat = center_lng = None
        if lat is not None and lng is not None and lat != "" and lng != "":
            try:
                center_lat = float(lat)
                center_lng = float(lng)
            except ValueError:
                return jsonify({"ok": False, "error": "Invalid lat/lng"}), 400
        radius = None
        if radius_miles:
            try:
                radius = float(radius_miles)
            except ValueError:
                return jsonify({"ok": False, "error": "Invalid radius_miles"}), 400

        rows = get_jobs(app.config["DATABASE"])
        out = []
        for r in rows:
            jlat = r.get("lat")
            jlng = r.get("lng")
            dist = None
            if center_lat is not None and jlat not in (None, "") and jlng not in (None, ""):
                try:
                    dist = haversine_miles(center_lat, center_lng, float(jlat), float(jlng))
                except Exception:
                    dist = None
            if radius is not None and dist is not None and dist > radius:
                continue
            out.append({
                "id": r["id"],
                "title": r["title"],
                "lat": float(jlat) if jlat not in (None, "") else None,
                "lng": float(jlng) if jlng not in (None, "") else None,
                "location_text": r.get("location_text"),
                "short_location": short_addr_from_display(r.get("location_text")),
                "tags": r.get("tags"),
                "distance_miles": round(dist, 2) if dist is not None else None,
            })
        return jsonify({"ok": True, "jobs": out})
    except Exception:
        app.logger.exception("API /api/jobs_nearby failed")
        return jsonify({"ok": False, "error": "Internal server error"}), 500


# --- Messaging & Reporting DB helpers ---
def ensure_warnings_table():
    """
    Create simple warnings table.
    """
    sql = """
    CREATE TABLE IF NOT EXISTS user_warnings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        conn.execute(sql)
        conn.commit()
    finally:
        conn.close()

ensure_warnings_table()

def ensure_messages_table():
    """
    Create messages table if it doesn't exist.
    Call this once on startup after init_db(...) has run.
    """
    sql = """
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0
    );
    """
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        conn.execute(sql)
        conn.commit()
    finally:
        conn.close()


def ensure_reports_table():
    sql = """
    CREATE TABLE IF NOT EXISTS message_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER NOT NULL,
        user_a INTEGER NOT NULL,
        user_b INTEGER NOT NULL,
        message_id INTEGER,
        message_snapshot TEXT,
        reason TEXT,
        created_at TEXT NOT NULL,
        status TEXT DEFAULT 'open'
    );
    """
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        conn.execute(sql)
        conn.commit()
    finally:
        conn.close()

def create_warning(db_path, user_id, admin_id, warning_type, message):
    """
    Create a warning for a user.
    """
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO admin_warnings (user_id, admin_id, warning_type, message, is_dismissed, created_at) VALUES (?, ?, ?, ?, 0, ?)",
            (int(user_id), int(admin_id), warning_type, message, now)
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

def get_user_unread_warnings(db_path, user_id):
    """
    Get unread warnings for a specific user.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM admin_warnings WHERE user_id = ? AND is_dismissed = 0 ORDER BY datetime(created_at) DESC",
            (int(user_id),)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def dismiss_warning(db_path, warning_id):
    """
    Mark a warning as dismissed.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE admin_warnings SET is_dismissed = 1 WHERE id = ?",
            (int(warning_id),)
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

def create_message(db_path, sender_id, recipient_id, body):
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "INSERT INTO messages (sender_id, recipient_id, body, created_at, is_read) VALUES (?, ?, ?, ?, 0)",
            (int(sender_id), int(recipient_id), body, now),
        )
        conn.commit()
        rowid = cur.lastrowid
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (rowid,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_conversation_rows(db_path, user_a, user_b, limit=500):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, sender_id, recipient_id, body, created_at, is_read
            FROM messages
            WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
            ORDER BY datetime(created_at) ASC
            LIMIT ?
            """,
            (user_a, user_b, user_b, user_a, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_conversations_summary(db_path, user_id, limit=50):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, sender_id, recipient_id, body, created_at, is_read
            FROM messages
            WHERE sender_id = ? OR recipient_id = ?
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (user_id, user_id, limit * 3),
        ).fetchall()

        summary = {}
        for r in rows:
            other = r["recipient_id"] if r["sender_id"] == user_id else r["sender_id"]
            if other not in summary:
                summary[other] = {
                    "other_id": other,
                    "last_message": r["body"],
                    "last_at": r["created_at"],
                    "last_sender_id": r["sender_id"],
                    "unread_count": 0,
                }
        unread_rows = conn.execute(
            """
            SELECT sender_id, recipient_id, COUNT(*) as cnt
            FROM messages
            WHERE recipient_id = ? AND is_read = 0
            GROUP BY sender_id
            """,
            (user_id,),
        ).fetchall()
        for ur in unread_rows:
            sender = ur["sender_id"]
            if sender in summary:
                summary[sender]["unread_count"] = ur["cnt"]

        out = sorted(summary.values(), key=lambda x: x["last_at"], reverse=True)
        return out
    finally:
        conn.close()


def mark_conversation_read(db_path, user_id, other_id):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE messages SET is_read = 1 WHERE recipient_id = ? AND sender_id = ? AND is_read = 0",
            (user_id, other_id),
        )
        conn.commit()
    finally:
        conn.close()


def create_report(db_path, reporter_id, user_a, user_b, message_id=None, message_snapshot=None, reason=None):
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO message_reports (reporter_id, user_a, user_b, message_id, message_snapshot, reason, created_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'open')",
            (int(reporter_id), int(user_a), int(user_b), message_id, message_snapshot, reason, now),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def get_reports(db_path, status=None, limit=200):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        if status:
            rows = conn.execute("SELECT * FROM message_reports WHERE status = ? ORDER BY datetime(created_at) DESC LIMIT ?", (status, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM message_reports ORDER BY datetime(created_at) DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_report_by_id(db_path, report_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM message_reports WHERE id = ?", (report_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# Ensure messaging and reports tables exist
ensure_messages_table()
ensure_reports_table()


# --- Routes / API for messaging / reports ---


@app.route("/messages")
@login_required
def messages_page():
    # pass current_user id to template for optional use by JS
    return render_template("messages.html", current_user_id=int(current_user.get_id()))


@app.route("/api/messages/conversations")
@login_required
def api_messages_conversations():
    uid = int(current_user.get_id())
    try:
        convs = get_conversations_summary(app.config["DATABASE"], uid)
        out = []
        for c in convs:
            other_row = get_user_by_id(app.config["DATABASE"], c["other_id"])
            display = other_row.get("username") or other_row.get("first_name") or other_row.get("email") or f"user-{c['other_id']}"
            out.append({
                "other_id": c["other_id"],
                "display": display,
                "last_message": c["last_message"],
                "last_at": c["last_at"],
                "last_sender_id": c["last_sender_id"],
                "unread_count": c["unread_count"],
            })
        return jsonify({"ok": True, "conversations": out})
    except Exception:
        app.logger.exception("Failed to fetch conversations")
        return jsonify({"ok": False, "error": "Internal server error"}), 500


@app.route("/api/messages/conversation/<int:other_id>")
@login_required
def api_messages_conversation(other_id):
    uid = int(current_user.get_id())
    other = get_user_by_id(app.config["DATABASE"], other_id)
    if not other:
        return jsonify({"ok": False, "error": "User not found"}), 404
    try:
        rows = get_conversation_rows(app.config["DATABASE"], uid, other_id)
        mark_conversation_read(app.config["DATABASE"], uid, other_id)
        return jsonify({"ok": True, "messages": rows})
    except Exception:
        app.logger.exception("Failed to fetch conversation")
        return jsonify({"ok": False, "error": "Internal server error"}), 500


@app.route("/api/messages/send", methods=["POST"])
@login_required
def api_messages_send():
    data = request.get_json() or {}
    recipient_id = data.get("recipient_id")
    body = (data.get("body") or "").strip()
    sender_id = int(current_user.get_id())
    if not recipient_id or not body:
        return jsonify({"ok": False, "error": "recipient_id and body required"}), 400
    recipient = get_user_by_id(app.config["DATABASE"], int(recipient_id))
    if not recipient:
        return jsonify({"ok": False, "error": "Recipient not found"}), 404
    try:
        msg = create_message(app.config["DATABASE"], sender_id, int(recipient_id), body)
        return jsonify({"ok": True, "message": msg})
    except Exception:
        app.logger.exception("Failed to send message")
        return jsonify({"ok": False, "error": "Internal server error"}), 500


@app.route("/api/messages/delete_conversation", methods=["POST"])
@login_required
def api_messages_delete_conversation():
    data = request.get_json() or {}
    other_id = data.get("other_id")
    if not other_id:
        return jsonify({"ok": False, "error": "other_id required"}), 400
    uid = int(current_user.get_id())
    try:
        conn = sqlite3.connect(app.config["DATABASE"])
        try:
            conn.execute(
                "DELETE FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)",
                (uid, int(other_id), int(other_id), uid),
            )
            conn.commit()
        finally:
            conn.close()
        return jsonify({"ok": True})
    except Exception:
        app.logger.exception("Failed to delete conversation")
        return jsonify({"ok": False, "error": "Internal server error"}), 500


@app.route("/api/messages/report", methods=["POST"])
@login_required
def api_messages_report():
    data = request.get_json() or {}
    other_id = data.get("other_id")
    reason = (data.get("reason") or "").strip()
    message_id = data.get("message_id")
    if not other_id or not reason:
        return jsonify({"ok": False, "error": "other_id and reason required"}), 400
    uid = int(current_user.get_id())
    other = get_user_by_id(app.config["DATABASE"], int(other_id))
    if not other:
        return jsonify({"ok": False, "error": "User not found"}), 404
    snapshot = None
    if message_id:
        try:
            conn = sqlite3.connect(app.config["DATABASE"])
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT body FROM messages WHERE id = ?", (int(message_id),)).fetchone()
            if row:
                snapshot = row["body"]
            conn.close()
        except Exception:
            app.logger.exception("Failed to fetch message snapshot")
            snapshot = None
    try:
        create_report(app.config["DATABASE"], uid, uid, int(other_id), message_id=message_id, message_snapshot=snapshot, reason=reason)
        return jsonify({"ok": True})
    except Exception:
        app.logger.exception("Failed to create report")
        return jsonify({"ok": False, "error": "Internal server error"}), 500


@app.route("/api/users/lookup")
@login_required
def api_users_lookup():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "error": "email query parameter required"}), 400
    try:
        row = get_user_by_email(app.config["DATABASE"], email)
        if not row:
            return jsonify({"ok": False, "error": "user not found"}), 404
        display = row.get("username") or row.get("first_name") or row.get("email") or f"user-{row.get('id')}"
        return jsonify({"ok": True, "user": {"id": row["id"], "display": display}})
    except Exception:
        app.logger.exception("User lookup failed")
        return jsonify({"ok": False, "error": "Internal server error"}), 500


# Admin endpoints to review reports and view conversations
@app.route("/admin/reports")
@require_roles("admin")
def admin_reports_page():
    # Get filter from query parameters
    status_filter = request.args.get('status')
    
    if status_filter:
        reports = get_reports(app.config["DATABASE"], status=status_filter)
    else:
        reports = get_reports(app.config["DATABASE"])
    
    # Enrich reports with user information
    for r in reports:
        r["reporter"] = get_user_by_id(app.config["DATABASE"], r["reporter_id"])
        r["user_a_obj"] = get_user_by_id(app.config["DATABASE"], r["user_a"])
        r["user_b_obj"] = get_user_by_id(app.config["DATABASE"], r["user_b"])
    
    return render_template("admin_reports.html", reports=reports)


@app.route("/api/admin/reports")
@require_roles("admin")
def api_admin_reports():
    try:
        rows = get_reports(app.config["DATABASE"])
        out = []
        for r in rows:
            out.append(r)
        return jsonify({"ok": True, "reports": out})
    except Exception:
        app.logger.exception("Failed to fetch admin reports")
        return jsonify({"ok": False, "error": "Internal server error"}), 500

@app.route("/admin/send-warning", methods=["POST"])
@require_roles("admin")
def admin_send_warning():
    user_id = request.form.get('user_id')
    message = request.form.get('message', '⚠️ Warning: Your behavior has been flagged.')
    
    if not user_id:
        flash("User ID required", "danger")
        return redirect(request.referrer or url_for('admin_dashboard'))
    
    create_simple_warning(app.config["DATABASE"], user_id, message)
    flash("Warning sent", "success")
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route("/api/admin/conversation")
@require_roles("admin")
def api_admin_conversation():
    try:
        user_a = request.args.get("user_a")
        user_b = request.args.get("user_b")
        if not user_a or not user_b:
            return jsonify({"ok": False, "error": "user_a and user_b required"}), 400
        rows = get_conversation_rows(app.config["DATABASE"], int(user_a), int(user_b))
        return jsonify({"ok": True, "messages": rows})
    except Exception:
        app.logger.exception("Failed to fetch admin conversation")
        return jsonify({"ok": False, "error": "Internal server error"}), 500


#
# Client dashboard and job routes (formerly employer)
#
@app.route("/client/dashboard")
@require_roles("client")
def client_dashboard():
    jobs = get_jobs_by_employer(app.config["DATABASE"], int(current_user.get_id()))
    return render_template("employer_dashboard.html", jobs=jobs)


@app.route("/post-job", methods=["GET", "POST"])
@require_roles("client")
def post_job():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location_text = request.form.get("location_text", "").strip() or None
        salary = request.form.get("salary", "").strip() or ""
        tags = request.form.get("tags", "").strip() or None

        lat_val = None
        lng_val = None
        lat_field = request.form.get("lat")
        lng_field = request.form.get("lng")
        try:
            if lat_field:
                lat_val = float(lat_field)
            if lng_field:
                lng_val = float(lng_field)
        except ValueError:
            lat_val = None
            lng_val = None

        if (lat_val is None or lng_val is None) and location_text:
            g_lat, g_lng, g_name = geocode_address(location_text)
            if g_lat is not None and g_lng is not None:
                lat_val = g_lat
                lng_val = g_lng

        if not title or not description:
            flash("Title and description are required.", "danger")
            return render_template("post_job.html", title=title, description=description, location_text=location_text, salary=salary, tags=tags, lat=lat_field, lng=lng_field)

        employer_id = int(current_user.get_id())
        try:
            job = create_job(
                app.config["DATABASE"],
                employer_id,
                title,
                description,
                location_text=location_text,
                lat=lat_val,
                lng=lng_val,
                salary=salary,
                tags=tags,
            )
            flash("Job posted.", "success")
            return redirect(url_for("client_dashboard"))
        except Exception as e:
            app.logger.exception("Failed to create job: %s", e)
            flash("Unable to create job.", "danger")
            return render_template("post_job.html", title=title, description=description, location_text=location_text, salary=salary, tags=tags, lat=lat_field, lng=lng_field)

    return render_template("post_job.html")


@app.route("/job/<int:job_id>")
@login_required
def job_detail(job_id):
    job = get_job_by_id(app.config["DATABASE"], job_id)
    if not job:
        flash("Job not found.", "warning")
        return redirect(url_for("jobs_list"))
    employer = get_user_by_id(app.config["DATABASE"], job["employer_id"])
    is_owner = False
    try:
        is_owner = (current_user.is_authenticated
                    and current_user.role == "client"
                    and int(current_user.get_id()) == int(job["employer_id"]))
    except Exception:
        is_owner = False
    return render_template("job_detail.html", job=job, employer=employer, is_owner=is_owner)


@app.route("/jobs/<int:job_id>")
@login_required
def job_detail_alias(job_id):
    return redirect(url_for("job_detail", job_id=job_id))


@app.route("/jobs/<int:job_id>/edit", methods=["GET", "POST"])
@require_roles("client")
def edit_job(job_id):
    job = get_job_by_id(app.config["DATABASE"], job_id)
    if not job:
        flash("Job not found.", "warning")
        return redirect(url_for("client_dashboard"))
    if int(job["employer_id"]) != int(current_user.get_id()):
        flash("You don't have permission to edit that job.", "danger")
        return redirect(url_for("client_dashboard"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location_text = request.form.get("location_text", "").strip() or None
        salary = request.form.get("salary", "").strip() or ""
        tags = request.form.get("tags", "").strip() or None
        lat_val = None
        lng_val = None
        lat_field = request.form.get("lat")
        lng_field = request.form.get("lng")
        try:
            if lat_field:
                lat_val = float(lat_field)
            if lng_field:
                lng_val = float(lng_field)
        except ValueError:
            lat_val = None
            lng_val = None
        if (lat_val is None or lng_val is None) and location_text:
            g_lat, g_lng, g_name = geocode_address(location_text)
            if g_lat is not None and g_lng is not None:
                lat_val = g_lat
                lng_val = g_lng
        if not title or not description:
            flash("Title and description are required.", "danger")
            return render_template("edit_job.html", job=job)
        try:
            updated = update_job(
                app.config["DATABASE"],
                job_id,
                title=title,
                description=description,
                location_text=location_text,
                lat=lat_val,
                lng=lng_val,
                salary=salary,
                tags=tags,
            )
            flash("Job updated.", "success")
            return redirect(url_for("job_detail", job_id=job_id))
        except Exception as e:
            app.logger.exception("Failed to update job: %s", e)
            flash("Unable to update job.", "danger")
            return render_template("edit_job.html", job=job)
    return render_template("edit_job.html", job=job)

@app.route("/warning/<int:warning_id>/dismiss", methods=["POST"])
@login_required
def dismiss_warning_route(warning_id):
    """
    Dismiss a warning.
    """
    try:
        user_id = int(current_user.get_id())
        
        # Verify warning belongs to user
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        warning = conn.execute(
            "SELECT * FROM admin_warnings WHERE id = ? AND user_id = ?",
            (warning_id, user_id)
        ).fetchone()
        conn.close()
        
        if warning:
            dismiss_warning(app.config["DATABASE"], warning_id)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Warning not found"}), 404
            
    except Exception as e:
        app.logger.exception("Failed to dismiss warning")
        return jsonify({"success": False, "error": "Server error"}), 500

@app.route("/jobs/<int:job_id>/delete", methods=["POST"])
@require_roles("client")
def delete_job_view(job_id):
    job = get_job_by_id(app.config["DATABASE"], job_id)
    if not job:
        flash("Job not found.", "warning")
        return redirect(url_for("client_dashboard"))
    if int(job["employer_id"]) != int(current_user.get_id()):
        flash("You don't have permission to delete that job.", "danger")
        return redirect(url_for("client_dashboard"))
    try:
        delete_job(app.config["DATABASE"], job_id)
        flash("Job deleted.", "success")
    except Exception as e:
        app.logger.exception("Failed to delete job: %s", e)
        flash("Unable to delete job.", "danger")
    return redirect(url_for("client_dashboard"))


#
# Submit rating (used by profile and job pages)
#
@app.route("/submit-rating", methods=["POST"])
@login_required
def submit_rating():
    target_type = (request.form.get("target_type") or "user").strip()
    target_id = request.form.get("target_id")
    rating_val = request.form.get("rating")
    comment = (request.form.get("comment") or "").strip()
    if not target_id or not rating_val:
        flash("Missing rating data.", "danger")
        return redirect(request.referrer or url_for("index"))
    try:
        target_id_i = int(target_id)
        rating_i = int(rating_val)
    except ValueError:
        flash("Invalid rating or target id.", "danger")
        return redirect(request.referrer or url_for("index"))
    if rating_i < 1 or rating_i > 5:
        flash("Rating must be between 1 and 5.", "danger")
        return redirect(request.referrer or url_for("index"))
    try:
        if target_type == "user" and int(current_user.get_id()) == target_id_i:
            flash("You cannot rate yourself.", "warning")
            return redirect(url_for("profile", user_id=target_id_i))
    except Exception:
        pass
    if target_type == "user":
        tgt = get_user_by_id(app.config["DATABASE"], target_id_i)
        if not tgt:
            flash("User not found.", "warning")
            return redirect(request.referrer or url_for("index"))
    elif target_type == "job":
        tgt = get_job_by_id(app.config["DATABASE"], target_id_i)
        if not tgt:
            flash("Job not found.", "warning")
            return redirect(request.referrer or url_for("index"))
    else:
        flash("Invalid rating target type.", "danger")
        return redirect(request.referrer or url_for("index"))
    try:
        create_rating(
            app.config["DATABASE"],
            target_type,
            target_id_i,
            int(current_user.get_id()),
            rating_i,
            comment,
        )
        flash("Thanks — your rating has been recorded.", "success")
    except Exception as e:
        app.logger.exception("Failed to save rating: %s", e)
        flash("Unable to save rating. Try again later.", "danger")
    if target_type == "user":
        return redirect(url_for("profile", user_id=target_id_i))
    else:
        return redirect(url_for("job_detail", job_id=target_id_i))

@app.route("/api/check-warnings")
@login_required
def api_check_warnings():
    """
    Check if user has unread warnings.
    """
    try:
        user_id = int(current_user.get_id())
        warnings = get_user_unread_warnings(app.config["DATABASE"], user_id)
        
        return jsonify({
            "has_warnings": len(warnings) > 0,
            "warnings": warnings,
            "count": len(warnings)
        })
    except Exception as e:
        app.logger.exception("Failed to check warnings")
        return jsonify({"has_warnings": False, "warnings": [], "count": 0})

#
# Admin dashboard and actions
#
@app.route("/admin/dashboard")
@require_roles("admin")
def admin_dashboard():
    users = get_all_users(app.config["DATABASE"])
    
    # Fetch reports for the dashboard
    reports = get_reports(app.config["DATABASE"], status="open")
    
    # Enrich reports with user information
    for report in reports:
        report["reporter"] = get_user_by_id(app.config["DATABASE"], report["reporter_id"])
        report["user_a_obj"] = get_user_by_id(app.config["DATABASE"], report["user_a"])
        report["user_b_obj"] = get_user_by_id(app.config["DATABASE"], report["user_b"])
    
    tpl_path = os.path.join(BASE_DIR, "templates", "admin_dashboard.html")
    if os.path.exists(tpl_path):
        return render_template("admin_dashboard.html", users=users, reports=reports)
    
    # Fallback template if admin_dashboard.html doesn't exist
    rows_html = ""
    for u in users:
        rows_html += "<li>{id}: {email} — role={role} — verified={verified}</li>".format(
            id=u.get("id"), email=u.get("email"), role=u.get("role"), verified=bool(u.get("verified"))
        )
    
    reports_html = ""
    for r in reports:
        reports_html += f"<li>Report #{r['id']}: {r.get('reason', 'No reason')} (Status: {r.get('status', 'open')})</li>"
    
    html = f"""
    <html>
      <head><title>Admin dashboard</title></head>
      <body>
        <h2>Admin dashboard</h2>
        
        <h3>Reported Conversations</h3>
        <ul>{reports_html}</ul>
        
        <h3>Users</h3>
        <ul>{rows_html}</ul>
        
        <p><a href="{url_for('index')}">Home</a></p>
      </body>
    </html>
    """
    return render_template_string(html)

@app.route("/admin/reports/<int:report_id>/resolve", methods=["POST"])
@require_roles("admin")
def admin_resolve_report(report_id):
    success = update_report_status(app.config["DATABASE"], report_id, "resolved")
    if success:
        flash("Report marked as resolved.", "success")
    else:
        flash("Failed to update report status.", "danger")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@require_roles("admin")
def admin_ban_user(user_id):
    days = request.form.get("days")
    banned_until_iso = None
    if days:
        try:
            days_i = int(days)
            banned_until = datetime.utcnow() + timedelta(days=days_i)
            banned_until_iso = banned_until.isoformat()
        except Exception:
            banned_until_iso = None
    set_user_ban(app.config["DATABASE"], user_id, banned_until_iso)
    flash("User has been banned.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/unban", methods=["POST"])
@require_roles("admin")
def admin_unban_user(user_id):
    unset_user_ban(app.config["DATABASE"], user_id)
    flash("User has been unbanned.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@require_roles("admin")
def admin_delete_user(user_id):
    try:
        if current_user.is_authenticated and int(current_user.get_id()) == int(user_id):
            flash("You cannot delete your own admin account.", "danger")
            return redirect(url_for("admin_dashboard"))
    except Exception:
        pass
    delete_user(app.config["DATABASE"], user_id)
    flash("User and their related data have been deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/purge-tokens", methods=["POST"])
@require_roles("admin")
def admin_purge_tokens():
    purge_expired_tokens(app.config["DATABASE"])
    flash("Expired tokens purged.", "success")
    return redirect(url_for("admin_dashboard"))


# Small helper endpoint used by messages.js to get the current user id
@app.route("/api/me")
@login_required
def api_me():
    try:
        return jsonify({"ok": True, "id": int(current_user.get_id())})
    except Exception:
        return jsonify({"ok": False}), 500

@app.route("/check-warnings")
@login_required
def check_warnings():
    user_id = int(current_user.get_id())
    warnings = get_user_warnings(app.config["DATABASE"], user_id)
    
    # Return and DELETE warnings (one-time display)
    if warnings:
        # Delete after showing
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.execute("DELETE FROM user_warnings WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
    
    return jsonify({"warnings": warnings})

if __name__ == "__main__":
    # For local development only
    app.run(debug=True)
