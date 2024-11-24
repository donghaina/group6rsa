from flask import Flask, render_template, jsonify, request
from flask_restful import Resource, Api, reqparse
# from rsa_functions import *

from RSA_file import *

app = Flask(__name__)
api = Api(app)

parser = reqparse.RequestParser()


@app.route('/')
def home():
    return render_template('index.html')


class GenerateKeys(Resource):
    def get(self):
        # print(request.args.get('keyLength'));
        # n, e, d = create_keys(1024)
        # return {
        # 'n': n,
        # 'd': d,
        # 'e': e
        # }
        return generateKeys(1024)


class EncryptMessage(Resource):
    def post(self):
        parser.add_argument('publicKey')
        parser.add_argument('plaintext')
        args = parser.parse_args()
        print(args)
        return encrypt_message(args['publicKey'], args['plaintext']);


class DecryptMessage(Resource):
    def post(self):
        parser.add_argument('privateKey')
        parser.add_argument('ciphertext')
        args = parser.parse_args()
        print(args)
        return decrypt_message(args['privateKey'], args['ciphertext']);


api.add_resource(GenerateKeys, '/generateKeys')
api.add_resource(EncryptMessage, '/encrypt')
api.add_resource(DecryptMessage, '/decrypt')

if __name__ == '__main__':
    app.run()
