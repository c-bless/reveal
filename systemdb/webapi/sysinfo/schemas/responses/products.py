from systemdb.webapi.extentions import ma
from systemdb.core.models.sysinfo import Product


class ProductSchema(ma.SQLAlchemyAutoSchema):
    """
    Installed Product

    """
    class Meta:
        model = Product
        include_fk = True
