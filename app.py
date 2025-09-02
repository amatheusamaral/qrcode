import os
import io
import csv
from datetime import datetime
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    url_for,
    flash,
    abort,
    send_file,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, URL, Length, Email, Regexp
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, scoped_session

import qrcode

from models import Base, User, Campaign, CampaignHistory

load_dotenv()


def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me")

    # ✅ Habilita proteção CSRF (necessário para o formulário de rollback no histórico)
    CSRFProtect(app)

    db_url = os.getenv("DATABASE_URL", "sqlite:///qr.db")

    # SQLAlchemy (sem Flask-SQLAlchemy para manter simples)
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {},
    )
    Base.metadata.create_all(engine)
    Session = scoped_session(sessionmaker(bind=engine))

    # Auth
    login_manager = LoginManager(app)
    login_manager.login_view = "login"

    @login_manager.user_loader
    def load_user(user_id):
        with Session() as s:
            return s.get(User, int(user_id))

    # bootstrap admin default
    def bootstrap_admin():
        admin_email = os.getenv("ADMIN_EMAIL")
        admin_pass = os.getenv("ADMIN_PASSWORD")
        if not admin_email or not admin_pass:
            return
        with Session() as s:
            exists = s.scalar(select(User).where(User.email == admin_email))
            if not exists:
                u = User(email=admin_email, is_admin=True)
                u.set_password(admin_pass)
                s.add(u)
                s.commit()

    bootstrap_admin()

    # Forms
    class LoginForm(FlaskForm):
        email = StringField("E-mail", validators=[DataRequired(), Email()])
        password = PasswordField("Senha", validators=[DataRequired()])

    class CampaignForm(FlaskForm):
        name = StringField("Nome da campanha", validators=[DataRequired(), Length(max=255)])
        slug = StringField(
            "Slug (URL)",
            validators=[
                DataRequired(),
                Length(max=100),
                Regexp(r"^[a-z0-9-]+$", message="Use apenas letras minúsculas, números e hífens"),
            ],
        )
        current_url = StringField(
            "URL de destino",
            validators=[DataRequired(), URL(require_tld=True, message="URL inválida")],
        )
        active = BooleanField("Ativa")

    def require_admin():
        if not (current_user.is_authenticated and current_user.is_admin):
            abort(403)

    # Public redirect
    @app.get("/qr/<slug>")
    def go(slug):
        with Session() as s:
            camp = s.scalar(select(Campaign).where(Campaign.slug == slug, Campaign.active == True))
            if not camp:
                abort(404)
            camp.clicks += 1
            camp.updated_at = datetime.utcnow()
            s.commit()
            return redirect(camp.current_url, code=302)

    # Auth routes
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = LoginForm()
        if form.validate_on_submit():
            with Session() as s:
                user = s.scalar(select(User).where(User.email == form.email.data))
                if user and user.check_password(form.password.data):
                    login_user(user)
                    return redirect(url_for("dashboard"))
            flash("Credenciais inválidas", "danger")
        return render_template("login.html", form=form)

    @app.get("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    # Admin: dashboard
    @app.get("/")
    @login_required
    def dashboard():
        require_admin()
        q = request.args.get("q", "").strip().lower()
        with Session() as s:
            stmt = select(Campaign).order_by(Campaign.updated_at.desc())
            items = s.scalars(stmt).all()
            if q:
                items = [c for c in items if q in c.name.lower() or q in c.slug.lower()]
        return render_template("dashboard.html", campaigns=items, q=q)

    # Create campaign
    @app.route("/campaign/new", methods=["GET", "POST"])
    @login_required
    def campaign_new():
        require_admin()
        form = CampaignForm()
        if form.validate_on_submit():
            with Session() as s:
                if s.scalar(select(Campaign).where(Campaign.slug == form.slug.data)):
                    flash("Slug já existe. Escolha outro.", "warning")
                else:
                    c = Campaign(
                        name=form.name.data,
                        slug=form.slug.data,
                        current_url=form.current_url.data,
                        active=form.active.data,
                    )
                    s.add(c)
                    # histórico inicial
                    s.flush()
                    h = CampaignHistory(
                        campaign_id=c.id,
                        old_url=form.current_url.data,
                        new_url=form.current_url.data,
                        changed_by_id=current_user.id,
                    )
                    s.add(h)
                    s.commit()
                    flash("Campanha criada!", "success")
                    return redirect(url_for("dashboard"))
        return render_template("campaign_form.html", form=form, mode="new")

    # Edit campaign
    @app.route("/campaign/<int:cid>/edit", methods=["GET", "POST"])
    @login_required
    def campaign_edit(cid):
        require_admin()
        with Session() as s:
            c = s.get(Campaign, cid)
            if not c:
                abort(404)
            form = CampaignForm(obj=c)
            # slug bloqueado na edição para evitar quebrar QR já impresso
            form.slug.render_kw = {"readonly": True}
            if form.validate_on_submit():
                old = c.current_url
                c.name = form.name.data
                c.current_url = form.current_url.data
                c.active = form.active.data
                c.updated_at = datetime.utcnow()
                # salva histórico apenas se a URL mudou
                if old != c.current_url:
                    h = CampaignHistory(
                        campaign_id=c.id,
                        old_url=old,
                        new_url=c.current_url,
                        changed_by_id=current_user.id,
                    )
                    s.add(h)
                s.commit()
                flash("Campanha atualizada!", "success")
                return redirect(url_for("dashboard"))
        return render_template("campaign_form.html", form=form, mode="edit", campaign=c)

    # History + rollback
    @app.get("/campaign/<int:cid>/history")
    @login_required
    def campaign_history(cid):
        require_admin()
        with Session() as s:
            c = s.get(Campaign, cid)
            if not c:
                abort(404)
            return render_template("history.html", campaign=c)

    @app.post("/campaign/<int:cid>/rollback/<int:hid>")
    @login_required
    def campaign_rollback(cid, hid):
        require_admin()
        with Session() as s:
            c = s.get(Campaign, cid)
            h = s.get(CampaignHistory, hid)
            if not c or not h or h.campaign_id != c.id:
                abort(404)
            old = c.current_url
            c.current_url = h.old_url
            c.updated_at = datetime.utcnow()
            s.add(
                CampaignHistory(
                    campaign_id=c.id,
                    old_url=old,
                    new_url=c.current_url,
                    changed_by_id=current_user.id,
                )
            )
            s.commit()
            flash("URL restaurada a uma versão anterior.", "info")
            return redirect(url_for("campaign_history", cid=cid))

    # ======= NOVO: Download do QR (PNG) por campanha =======
    @app.get("/campaign/<int:cid>/qr.png")
    @login_required
    def campaign_qr(cid):
        require_admin()
        with Session() as s:
            c = s.get(Campaign, cid)
            if not c:
                abort(404)
            # monta URL pública do redirecionamento
            url = request.url_root.rstrip("/") + url_for("go", slug=c.slug)
            img = qrcode.make(url)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            return send_file(
                buf,
                mimetype="image/png",
                as_attachment=True,
                download_name=f"qr-{c.slug}.png",
            )

    # ======= NOVO: Exportação CSV com estatísticas =======
    @app.get("/export.csv")
    @login_required
    def export_csv():
        require_admin()
        with Session() as s:
            items = s.scalars(select(Campaign).order_by(Campaign.created_at)).all()
        buf_txt = io.StringIO()
        writer = csv.writer(buf_txt)
        writer.writerow(
            ["ID", "Nome", "Slug", "URL atual", "Cliques", "Ativa", "Criada em", "Atualizada em"]
        )
        for c in items:
            writer.writerow(
                [
                    c.id,
                    c.name,
                    c.slug,
                    c.current_url,
                    c.clicks,
                    "sim" if c.active else "não",
                    c.created_at.strftime("%Y-%m-%d %H:%M"),
                    c.updated_at.strftime("%Y-%m-%d %H:%M"),
                ]
            )
        buf_txt.seek(0)
        return send_file(
            io.BytesIO(buf_txt.getvalue().encode("utf-8")),
            mimetype="text/csv",
            as_attachment=True,
            download_name="campanhas.csv",
        )

    # helper para validar URL (opcional, já temos validator)
    def is_valid_url(u: str) -> bool:
        try:
            p = urlparse(u)
            return p.scheme in ("http", "https") and p.netloc
        except Exception:
            return False

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
