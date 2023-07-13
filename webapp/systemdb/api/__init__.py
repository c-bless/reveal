from flask_smorest import Api

api = Api()


def register_api(app):
    api.init_app(app)

    from webapp.systemdb.api.auth.resources import blp as auth_bp
    api.register_blueprint(auth_bp)

    from webapp.systemdb.api.sysinfo.resources.software import blp as software_bp
    api.register_blueprint(software_bp)

    from webapp.systemdb.api.sysinfo.resources.hosts import blp as hosts_bp
    api.register_blueprint(hosts_bp)

    from webapp.systemdb.api.sysinfo.resources.reports import blp as reports_bp
    api.register_blueprint(reports_bp)

    from webapp.systemdb.api.ad.resources.domain import blp as addomain_bp
    api.register_blueprint(addomain_bp)

    from webapp.systemdb.api.ad.resources.forest import blp as adforest_bp
    api.register_blueprint(adforest_bp)







