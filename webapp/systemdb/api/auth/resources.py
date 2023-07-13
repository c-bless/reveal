from http import HTTPStatus

from flask import abort
from flask.views import MethodView
from flask_jwt_extended import create_access_token, jwt_required, get_jwt

from webapp.systemdb.api.auth import blp
from webapp.systemdb.api.auth.blocklist import BLOCKLIST
from webapp.systemdb.api.auth.schema import AuthUserSchema
from webapp.systemdb.models.auth import AuthUser


@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(AuthUserSchema)
    def post(self, user_data):
        user = AuthUser.query.filter(AuthUser.Username == user_data["username"]).first()
        if user is None or not user.check_password(user_data["password"]):
            access_token = create_access_token(identity=user.UUID)
            return {"access_token": access_token}, HTTPStatus.OK

        abort(HTTPStatus.UNAUTHORIZED, message="Invalid credentials.")


@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"message": "Successfully logged out"}, HTTPStatus.OK
