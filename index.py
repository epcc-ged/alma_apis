# see https://developers.exlibrisgroup.com/alma/integrations/webhooks/anatomy/
import hashlib
import hmac
import base64
import logging
from os import environ
from flask import Flask, jsonify, request, Response

app = Flask(__name__)
# load secret from environment
# Remember to export ALMA_USER_SECRET=my_secret_string
app.config['ALMA_USER_SECRET'] = environ.get('ALMA_USER_SECRET')

@app.route('/')
def index():
    return """
        <h1>This is the Alma APIs Middleware server</h1>
        <p>See README in repository : <a href="https://github.com/epcc-ged/alma_apis">https://github.com/epcc-ged/alma_apis</a></p>
        <p>Available endpoints:</p>
        <ul>
            <li>/webhook-export-user</li>
        </ul>
    """

# /webhook-export-user GET
# accept the challenge from Alma for this API endpoint
@app.route('/webhook-export-user', methods=["GET"])
def export_user_get():
    challenge = request.args.get('challenge', '')
    return jsonify({'challenge': challenge})


# /webhook-export-user POST, get the payload
# validate signature
# TODO: use the payload, i.e. user account data
@app.route('/webhook-export-user', methods=["POST"])
def export_user_post():
    exl_signature = request.headers.get('X-Exl-Signature', None)
    if not exl_signature:
        return bad_request('Missing X-Exl-Signature')
    secret = app.config['ALMA_USER_SECRET']
    body = request.get_data()
    valid = validate_signature(body, secret.encode('utf-8'), exl_signature.encode('utf-8'))
    if valid:
        return 'Signature is valid. TODO: parse body and actually do something with it'
    else:
        return access_forbidden('Signature not valid')

# validate Ex Libris signature
def validate_signature(body, secret, signature):
    verify = base64.b64encode(hmac.new(secret, body, digestmod=hashlib.sha256).digest())
    return verify == signature

@app.errorhandler(403)
def access_forbidden(error='HTTP_403_FORBIDDEN'):
    message = {
            'status': 403,
            'message': error
    }
    resp = jsonify(message)
    resp.status_code = 400
    return resp

@app.errorhandler(400)
def bad_request(error='HTTP_400_BAD_REQUEST'):
    message = {
        'status': 400,
        'message': error
    }
    resp = jsonify(message)
    resp.status_code = 400
    return resp