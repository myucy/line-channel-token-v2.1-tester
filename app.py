# -*- coding: utf-8 -*-

#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from argparse import ArgumentParser
import json

import requests

from flask import Flask, request, abort, render_template, jsonify, redirect, session, make_response

from jwcrypto import jwk,jwt
from jwcrypto.common import json_encode
import time

import ast



app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False


@app.route('/oauth2/v2.1/jwt', methods=['POST'])
def jwtissue():
    postdata = json.loads(request.data)
    header = postdata['header'] 
    payload = postdata['payload'] 
    privatekey = postdata['privatekey']
 
    header = ast.literal_eval(header)
    payload = ast.literal_eval(payload)
    privatekey = ast.literal_eval(privatekey)
 
    privatekey = jwk.JWK(**privatekey)
    JWT = jwt.JWT(header=header,claims=payload)

    JWT.make_signed_token(privatekey)
    JWT = JWT.serialize()

    params = {
        'response_body':JWT 
        }
    return jsonify(params)

@app.route('/oauth2/v2.1/jwt', methods=['GET'])
def jwtGET():

    return render_template('jwt.html',
    exp=(int(time.time()))+(60 * 30)
    )

@app.route('/oauth2/v2.1/token', methods=['GET'])
def issue():

    return render_template('token.html')


@app.route('/oauth2/v2.1/token', methods=['POST'])
def issuetoken():
    postdata = json.loads(request.data)
    res_raw = requests.post("https://api.line.me/oauth2/v2.1/token",
                            headers={
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            data={
                                'grant_type':  postdata['grant_type'],
                                'client_assertion_type':  postdata['client_assertion_type'],
                                'client_assertion':  postdata['client_assertion'],
                            })
    params = {
        'response_body':res_raw.json(),
        'response_status_code':res_raw.status_code
        }
    return jsonify(params)




@app.route('/oauth2/v2.1/tokens', methods=['GET'])
def tokens():

    return render_template('tokens.html')

@app.route('/oauth2/v2.1/tokens', methods=['POST'])
def gettokens():

    postdata = json.loads(request.data)
    res_raw = requests.get("https://api.line.me/oauth2/v2.1/tokens",
                            headers={
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            params={
                                'client_assertion_type':  postdata['client_assertion_type'],
                                'client_assertion':  postdata['client_assertion']
                                })
    
    params = {
        'response_body':res_raw.json(),
        'response_status_code':res_raw.status_code
        }
    return jsonify(params)

@app.route('/oauth2/v2.1/revoke', methods=['GET'])
def revoke():

    return render_template('revoke.html')

@app.route('/oauth2/v2.1/revoke', methods=['POST'])
def revoketoken():

    postdata = json.loads(request.data)
    res_raw = requests.post("https://api.line.me/oauth2/v2.1/revoke",
                            headers={
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            data={
                                'client_id':  postdata['client_id'],
                                'client_secret':  postdata['client_secret'],
                                'access_token':  postdata['access_token']
                                })

    try:
        res_raw.json()
    except :
        params = {
        'response_body':{},
        'response_status_code':res_raw.status_code
        }
        return jsonify(params)
    

    params = {
        'response_body':res_raw.json(),
        'response_status_code':res_raw.status_code
    }
    return jsonify(params)



if __name__ == "__main__":
    arg_parser = ArgumentParser(
        usage='Usage: python ' + __file__ + ' [--port <port>] [--help]'
    )
    arg_parser.add_argument('-p', '--port', type=int,
                            default=8000, help='port')
    arg_parser.add_argument('-d', '--debug', default=False, help='debug')
    options = arg_parser.parse_args()
    app.debug = True
    app.run(debug=False, port=options.port, threaded=True)
