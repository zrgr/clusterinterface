from flask import Blueprint

mod = Blueprint('api', __name__)


@mod.route('/get')
def getHash():
    return '{"hash" : "password"}'
