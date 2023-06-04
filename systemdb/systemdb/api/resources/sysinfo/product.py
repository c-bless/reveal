from flask_restful import Resource

from ... import api
from ....models.sysinfo import Product
from ...schema.sysinfo.product import products_schema, product_schema

class ProductResource(Resource):

    def get(self, id):
        """
           Returns the product with the specified id.

           ---
           tags:
             - products
           parameters:
             - in: path
               name: id
               type: integer
               required: true
           responses:
             404:
                description: No product with found under the specified id
             200:
               description: A single product
               content:
                    application/json:
                      schema:
                        $ref: '#/components/schemas/Product'

           """
        product = Product.query.get_or_404(id)
        return product_schema.dump(product)


class ProductListAllResource(Resource):

    def get(self):
        """
            Returns a list of all installed products from all hosts.

            ---
            tags:
             - products
            responses:
             200:
               description: list of products

            """
        products = Product.query.all()
        return products_schema.dump(products)


class ProductListByHostResource(Resource):

    def get(self, id):
        """
            Returns a list of all installed products from a specific host.

            ---
            tags:
             - products
             - hosts
            parameters:
             - in: path
               name: id
               type: integer
               required: true
            responses:
             200:
               description: list of products
               "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/definitions/Product"
                    }
                  }

            """
        products = Product.query.filter(Product.Host_id == id).all()
        return products_schema.dump(products)


api.add_resource(ProductResource, '/sysinfo/products/<int:id>', endpoint='product_by_id')
api.add_resource(ProductListAllResource, '/sysinfo/products/', endpoint='product_list')
api.add_resource(ProductListByHostResource, '/sysinfo/hosts/<int:id>/products/', endpoint='product_by_host')

