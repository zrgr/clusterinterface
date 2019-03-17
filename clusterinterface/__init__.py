from flask import Flask

app = Flask(__name__)

from clusterinterface.api.routes import mod
from clusterinterface.site.routes import mod


app.register_blueprint(site.routes.mod, url_prefix='/')
app.register_blueprint(api.routes.mod, url_prefix='/api')
