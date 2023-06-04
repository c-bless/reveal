from ...ma import ma
from ....models.sysinfo import Host


class HostSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Host
        include_relationships = True
        load_instance = True
        include_fk = True

host_schema = HostSchema()
hosts_schema = HostSchema(many=True)
