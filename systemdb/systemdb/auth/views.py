from flask import render_template, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user, current_user

from . import auth_bp
from .utils import gen_api_token
from .forms import LoginForm, ChangePasswordForm
from ..models.auth import AuthUser
from ..models.db import db


def is_url_allowed(url, host):
    return True


@auth_bp.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@auth_bp.route("/profile")
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@auth_bp.route("/renew-token")
@login_required
def renew_token():
    user = AuthUser.query.filter(AuthUser.UUID == current_user.UUID).first()
    user.API_TOKEN = gen_api_token()
    db.session.add(user)
    db.session.commit()
    return render_template('profile.html', user=user)


@auth_bp.route("/change-pw", methods=['POST'])
@login_required
def change_pw():
    form = ChangePasswordForm()
    user = AuthUser.query.filter(AuthUser.UUID == current_user.UUID).first()
    user.set_password(form.password.data)
    db.session.add(user)
    db.session.commit()
    return render_template('change-pw.html', user=user)


@auth_bp.route("/login", methods=['GET'])
def login():
    form = LoginForm()
    return render_template('login.html', form=form)


@auth_bp.route("/login", methods=['POST'])
def login_post():
    form = LoginForm()
    if form.validate_on_submit():
        user =  AuthUser.query.filter(AuthUser.Username == form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('auth.index'))

    return render_template('login.html', form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.index'))




