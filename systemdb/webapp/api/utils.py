

from flask import request, jsonify, make_response, abort
from functools import wraps

from systemdb.core.models.auth import AuthUser


# Authentication decorator
def token_required(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        print ("Decorator")
        if 'X-API-Key' in request.headers:
            auth_headers = request.headers.get('X-API-Key', '').split()
            if len(auth_headers) != 2:
                # Token missing
                return make_response(jsonify({"message": "Token Is Missing"}), 401)
            try:
                token = auth_headers[1]
                user = AuthUser.find_by_token(token)
                if user is None:
                    return make_response(jsonify({"message": "Token Is Invalid"}), 401)
                return func(user, *args, **kwargs)
            except:
                abort(401)
                return make_response(jsonify({"message": "Token Is Invalid"}), 401)

        return make_response(jsonify({"message": "'X-API-Key' header is missing"}), 401)
    return decorator