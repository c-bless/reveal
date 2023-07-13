from webapp.systemdb.api.ma import ma
from webapp.systemdb.models.sysinfo import Product


class ProductSchema(ma.SQLAlchemyAutoSchema):
    """
    Installed Product

    """
    class Meta:
        model = Product
        include_fk = True
