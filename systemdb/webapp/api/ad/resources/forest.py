from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from sqlalchemy import and_

from systemdb.core.models.activedirectory import ADForest
from systemdb.core.models.activedirectory import ADForestSite
from systemdb.core.models.activedirectory import ADForestGlobalCatalog
from systemdb.core.models.activedirectory import ADGroup
from systemdb.core.models.activedirectory import ADDomain

from systemdb.webapp.api.ad.schemas.responses.domain import ADForestGlobalCatalogSchema
from systemdb.webapp.api.ad.schemas.responses.domain import ADForestSchema
from systemdb.webapp.api.ad.schemas.responses.domain import ADForestSiteSchema
from systemdb.webapp.api.ad.schemas.responses.domain import ADGroupWithMembersSchema

blp = Blueprint('ActiveDirectory - Forest', 'ad_forest_api' , url_prefix='/api/ad',
             description="Review active directory data collected by domain-collector PowerShell scripts.")


@blp.route("/forest/<int:id>")
class ForestByIdView(MethodView):

    @blp.doc(description="Returns the forest with the specified id.",
             summary="Find a forest by ID"
             )
    @blp.response(HTTPStatus.OK.value, ADForestSchema, description= "Forest with specified ID")
    def get(self, id):
        return ADForest.query.get_or_404(id)


@blp.route("/forest/by-name/<string:name>")
class ForestByNameView(MethodView):

    @blp.doc(description="Returns a list of forests containing the specified name.",
             summary="Find forest by name"
             )
    @blp.response(HTTPStatus.OK.value, ADForestSchema(many=True),
                  description="List of forests")
    def get(self, name):
        return ADForest.query.filter(ADForest.Name.like("%"+name+"%")).all()


@blp.route("/forest/")
class ForestListView(MethodView):

    @blp.doc(description="Returns a list of all forests. In case no forest is found an empty list is returned.",
             summary="Find all forest."
             )
    @blp.response(HTTPStatus.OK.value, ADForestSchema(many=True))
    def get(self):
        return ADForest.query.all()


@blp.route("/forest/<int:forest_id>/globalcatalogs/")
class ForestGlobalCatalogListView(MethodView):

    @blp.doc(description="Returns a list of all global catalogs in the forest with the specified ID.",
             summary="Find a list of all global catalogs in the forest with the specified ID."
             )
    @blp.response(HTTPStatus.OK.value, ADForestGlobalCatalogSchema(many=True),
                  description="List of global catalogs.")
    def get(self, forest_id):
        try:
            return ADForestGlobalCatalog.query.filter(ADForestGlobalCatalog.Forest_id == forest_id).all()
        except:
            abort(404, "Forest not found.")


@blp.route("/forest/<int:forest_id>/sites/")
class ForestGlobalCatalogListView(MethodView):

    @blp.doc(description="Returns a list of sites for the forest with the specified ID.",
             summary="Find a list of sites for the forest with the specified ID."
             )
    @blp.response(HTTPStatus.OK.value, ADForestSiteSchema(many=True),
                  description="List of sites.")
    def get(self, forest_id):
        try:
            return ADForestSite.query.filter(ADForestSite.Forest_id == forest_id).all()
        except:
            abort(404, "Forest not found.")


@blp.route("/forest/<int:forest_id>/groups/enterpriseadmins/")
class ForestEnterpriseAdminGroupView(MethodView):

    @blp.doc(description="Returns the enterprise admin group for the specified forest.",
             summary="Find the enterprise admin group for the specified forest."
             )
    @blp.response(HTTPStatus.OK.value, ADGroupWithMembersSchema, description="Enterprise Admin group")
    def get(self, forest_id):
        try:
            forest = ADForest.query.get_or_404(forest_id)
            domains = ADDomain.query.filter(ADDomain.DNSRoot == forest.Name).all()
            ids = [d.id for d in domains]
            return ADGroup.query.filter(
                and_(ADGroup.SamAccountName == "Enterprise Admins", ADDomain.id.in_(ids))).first()
        except:
            abort(404, "Domain/Group not found.")
