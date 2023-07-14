from http import HTTPStatus

from flask import abort
from flask.views import MethodView
from flask_jwt_extended import create_access_token, jwt_required, get_jwt, get_jwt_identity

from webapp.systemdb.api.auth import blp
from webapp.systemdb.api.auth.blocklist import BLOCKLIST
from webapp.systemdb.api.auth.schema import AuthUserSchema
from webapp.systemdb.models.auth import AuthUser


@blp.route("/login")
class UserLogin(MethodView):


    @blp.doc(description="Login a user via API.",
             summary="Login a user"
             )
    @blp.arguments(AuthUserSchema, location='json')
    def post(self, user_data):
        print("Login1")
        user = AuthUser.query.filter(AuthUser.Username == user_data["username"]).first()
        print("Login 2")
        if user is None or not user.check_password(user_data["password"]):
            print("Login3")
            access_token = create_access_token(identity=user.UUID)

            print("Login4: {0}".format(access_token))
            return {"access_token": access_token}, HTTPStatus.OK

        abort(HTTPStatus.UNAUTHORIZED, message="Invalid credentials.")


@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"message": "Successfully logged out"}, HTTPStatus.OK


@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        # Make it clear that when to add the refresh token to the blocklist will depend on the app design
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"access_token": new_token}, HTTPStatus.OK