from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint
from sqlalchemy import and_


from ....models.activedirectory import ADDomain, ADUser, ADGroup, ADComputer
from ..schemas.responses.domain import ADDomainSchema, ADUserSchema, ADGroupSchema, ADComputerSchema

blp = Blueprint('ActiveDirectory - Domain', 'ad_domain_api' , url_prefix='/api/ad',
             description="Review active directory data collected by domain-collector PowerShell scripts.")


@blp.route("/domain/<int:id>")
class DomainByIdView(MethodView):

    @blp.doc(description="Returns the domain with the specified id.",
             summary="Find a domain by ID"
             )
    @blp.response(HTTPStatus.OK.value, ADDomainSchema)
    def get(self, id):
        return ADDomain.query.get_or_404(id)


@blp.route("/domain/by-name/<string:name>")
class DomainByNameView(MethodView):

    @blp.doc(description="Returns a list of domains containing the specified name.",
             summary="Find domains by name"
             )
    @blp.response(HTTPStatus.OK.value, ADDomainSchema(many=True))
    def get(self, name):
        return ADDomain.query.filter(ADDomain.Name.like("%"+name+ "%" )).all()


@blp.route("/domain/")
class DomainListView(MethodView):

    @blp.doc(description="Returns a list of all domains.",
             summary="Find all domain."
             )
    @blp.response(HTTPStatus.OK.value, ADDomainSchema(many=True))
    def get(self):
        return ADDomain.query.all()


@blp.route("/domain/<int:domain_id>/groups/domainadmins/")
class DomainListDomainAdminGroupView(MethodView):

    @blp.doc(description="Returns the domain admin group for the specified domain.",
             summary="Find the domain admin group for the specified domain."
             )
    @blp.response(HTTPStatus.OK.value, ADDomainSchema)
    def get(self, domain_id):
        return ADGroup.query.filter(and_(ADGroup.Domain_id == domain_id, ADGroup.SamAccountName == "Domain Admins")).first()


@blp.route("/domain/<int:domain_id>/users/")
class DomainListUsersView(MethodView):

    @blp.doc(description="Returns a list of all domain users for the domain with the specified ID.",
             summary="Find a list of all domain users for the domain with the specified ID."
             )
    @blp.response(HTTPStatus.OK.value, ADUserSchema(many=True))
    def get(self, domain_id):
        return ADUser.query.filter(ADUser.Domain_id == domain_id).all()


@blp.route("/domain/<int:domain_id>/groups/")
class DomainListGroupsView(MethodView):

    @blp.doc(description="Returns a list of all domain groups for the domain with the specified ID.",
             summary="Find a list of all domain groups for the domain with the specified ID."
             )
    @blp.response(HTTPStatus.OK.value, ADGroupSchema(many=True))
    def get(self, domain_id):
        return ADGroup.query.filter(ADGroup.Domain_id == domain_id).all()



@blp.route("/domain/<int:domain_id>/computers/")
class DomainListComputersView(MethodView):

    @blp.doc(description="Returns a list of all domain computers for the domain with the specified ID.",
             summary="Find a list of all domain computers for the domain with the specified ID."
             )
    @blp.response(HTTPStatus.OK.value, ADComputerSchema(many=True))
    def get(self, domain_id):
        return ADComputer.query.filter(ADComputer.Domain_id == domain_id).all()

