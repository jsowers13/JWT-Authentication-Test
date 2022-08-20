from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps


app = Flask(__name__)

app.config['SECRET_KEY'] = 'secretkey'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid'}), 403

        return f(*args, **kwargs)
    return decorated

@app.route('/protected')
@token_required
def protected():
    return jsonify({'message' : 'This is only viewable for those with valid tokens'})

@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'This is available for anyone to view'})

@app.route('/login')
def login():
    auth = request.authorization
    #generates token based off username and gives it an expiration of 30 minutes after creation
    if auth and auth.password == 'secret':
        token = jwt.encode({'user': auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token})
    return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})



if __name__ == '__main__':
    app.run(debug=True)
