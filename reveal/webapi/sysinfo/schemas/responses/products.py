from reveal.webapi.extentions import ma
from reveal.core.models.sysinfo import Product


class ProductSchema(ma.SQLAlchemyAutoSchema):
    """
    Installed Product

    """
    class Meta:
        model = Product
        include_fk = True
