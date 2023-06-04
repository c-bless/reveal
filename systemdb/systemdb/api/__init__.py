from flask import Blueprint
from flask_restful import Api
from flasgger import Swagger

api_bp = Blueprint('api', __name__, url_prefix='/api')
api = Api(api_bp)

from .resources.sysinfo.product import ProductListAllResource, ProductResource, ProductListByHostResource
from .resources.sysinfo.service import ServiceListAllResource, ServiceResource, ServiceListByHostResource
from .resources.sysinfo.hosts import HostResource, HostListAllResource

def add_apispec(app):
    template = {
        "swagger": "2.0",
        "info": {
            "title": "systemdb API",
            "description": "API for retrieving data collected by system-collector and domain-collector scripts.",
            "contact": {
                "responsibleDeveloper": "Christoph Bless",
                "email": "bitbucket@cbless.de",
                "url": "https://bitbucket.org/cbless/systemdb",
            },
            #"termsOfService": "https://bitbucket.org/cbless/systemdb/terms",
            "version": "0.2"
        },
        "host": "localhost:5000",  # overrides localhost:500
        "basePath": "/api",  # base bash for blueprint registration
        "schemes": [
            "http",
            "https"
        ],
        #"operationId": "getmyData",
        "components": {
            "schemas": {
                "Product": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "integer",
                            "description": "primary key"
                        },
                        "Caption": {
                            "type": "string",
                            "description": "Caption"
                        },
                        "InstallDate": {
                            "type": "string",
                            "description": "InstallDate"
                        },
                        "Description": {
                            "type": "string",
                            "description": "Description of the product"
                        },
                        "Vendor": {
                            "type": "string",
                            "description": "Vendor"
                        },
                        "Name": {
                            "type": "string",
                            "description": "Name"
                        },
                        "Version": {
                            "type": "string",
                            "description": "Version"
                        },
                        "InstallLocation": {
                            "type": "string",
                            "description": "InstallLocation"
                        },
                        "Host_id": {
                            "type": "integer",
                            "description": "foreign key (Host)"
                        }
                    }
                }
            },
        }
    }

    swagger = Swagger(app, template=template)

