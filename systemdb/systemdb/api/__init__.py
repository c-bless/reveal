from flask_smorest import Api

api = Api()


def register_api(app):
    api.init_app(app)

    from .sysinfo.resources.software import blp as software_bp
    api.register_blueprint(software_bp)

    from .sysinfo.resources.hosts import blp as hosts_bp
    api.register_blueprint(hosts_bp)

    from .sysinfo.resources.reports import blp as reports_bp
    api.register_blueprint(reports_bp)

    from .ad.resources.domain import blp as addomain_bp
    api.register_blueprint(addomain_bp)

    from .ad.resources.forest import blp as adforest_bp
    api.register_blueprint(adforest_bp)







