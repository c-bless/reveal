from flask_restful import Resource

from ... import api
from ....models.sysinfo import Host
from ...schema.sysinfo.hosts import host_schema, hosts_schema

class HostResource(Resource):

    def get(self, id):
        """
           Returns the host with the specified id.

           ---
           tags:
             - hosts
           parameters:
             - in: path
               name: id
               type: integer
               required: true
           responses:
             404:
                description: No host with found under the specified id
             200:
               description: A single host

           """
        host = Host.query.get_or_404(id)
        return host_schema.dump(host)


class HostListAllResource(Resource):

    def get(self):
        """
            Returns a list of all hosts.

            ---
            tags:
             - hosts
            responses:
             200:
               description: list of products

            """
        hosts = Host.query.all()
        return hosts_schema.dump(hosts)



api.add_resource(HostResource, '/sysinfo/hosts/<int:id>', endpoint='host_by_id')
api.add_resource(HostListAllResource, '/sysinfo/hosts/', endpoint='hosts_list')

