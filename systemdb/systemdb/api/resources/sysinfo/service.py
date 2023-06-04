from flask_restful import Resource

from ... import api
from ....models.sysinfo import Service, ServiceACL
from ...schema.sysinfo.service import service_schema, services_schema, serviceACL_schema, serviceACLs_schema


class ServiceResource(Resource):

    def get(self, id):
        """
           Returns a specific service.

           ---
           tags:
            - services
           parameters:
            - in: path
              name: id
              type: integer
              required: true
           responses:
             404:
                description: No service with found under the specified id
             200:
               description: A single service


           """
        service = Service.query.get_or_404(id)
        return service_schema.dump(service)


class ServiceListAllResource(Resource):

    def get(self):
        """
        Returns a list of all installed services from all hosts.

        ---
        tags:
         - services
        responses:
         200:
           description: list of services

        """
        services = Service.query.all()
        return services_schema.dump(services)


class ServiceListByHostResource(Resource):

    def get(self, id):
        """
        Returns a list of all installed services from a specific host.

            ---
            tags:
             - services
             - hosts
            parameters:
             - in: path
               name: id
               type: integer
               required: true
            responses:
             200:
               description: list of services
        """
        services = Service.query.filter(Service.Host_id == id).all()
        return services_schema.dump(services)


api.add_resource(ServiceResource, '/sysinfo/services/<int:id>', endpoint='service_by_id')
api.add_resource(ServiceListAllResource, '/sysinfo/services/', endpoint='service_list')
api.add_resource(ServiceListByHostResource, '/sysinfo/hosts/<int:id>/services/', endpoint='service_by_host')



class ServiceAclResource(Resource):

    def get(self, id):
        """
           Returns a specific ACL.

           ---
           tags:
            - services
           parameters:
            - in: path
              name: id
              type: integer
              required: true
           responses:
             404:
                description: No acl with found under the specified id
             200:
               description: A single ServiceACL


           """
        acl = ServiceACL.query.get_or_404(id)
        return serviceACL_schema.dump(acl)

class ServiceAclListByServiceResource(Resource):

    def get(self, id):
        """
        Returns a list ACLs for the specified service

            ---
            tags:
             - services
             - hosts
            parameters:
             - in: path
               name: id
               type: integer
               required: true
            responses:
             200:
               description: list of services
        """
        acls = ServiceACL.query.filter(ServiceACL.Service_id == id).all()
        return serviceACLs_schema.dump(acls)



api.add_resource(ServiceAclResource, '/sysinfo/serviceACLs/<int:id>', endpoint='service_acl_id')
api.add_resource(ServiceListAllResource, '/sysinfo/services/<int:id>/acls/', endpoint='service_acl_list')