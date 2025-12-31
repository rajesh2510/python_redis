import redis
import bcrypt
from flask import Flask, request, jsonify, session


app = Flask(__name__)
app.secret_key = 'super-secret-key-change-this' # Used for Flask session cookie signing
r = redis.Redis(host='localhost', port=6379,decode_responses=True)
@app.route('/signup', methods=['POST'])
def signup():
    data =request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not username or not email or not password:
        return jsonify({'message': 'Missing fields'}), 400
    if r.exists(f"email:{email}"):
        return jsonify({"message": "Email already registered, try login"}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    r.hset(f"email:{email}", mapping={
        'username': username,
        'email': email,
        'password': hashed_password.decode('utf-8')
    })
    return jsonify({'message': f'User {username} registered successfully'}), 201

@app.route('/login',methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Missing fields'}), 400
    user_data = r.hgetall(f"email:{email}")
    if not user_data:
        return jsonify({'message': 'User not found'}), 404
    if bcrypt.checkpw(password.encode('utf-8'), user_data['password'].encode('utf-8')):
        r.setex(f'session:{email}', 3600, user_data['username'])  # Session expires in 1 hour
        session['token'] = email
        return jsonify({'message': 'Login successful'}), 200
    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/protected', methods=['GET'])
def protected():
    # 1. Get token from cookie
    sess_email = session.get('token')
    if not sess_email:
        return jsonify({'message': 'Please login'}), 401 
    # 2. Check if session exists in Redis
    username = r.get(f'session:{sess_email}')
    if not username:
        return jsonify({'message': 'Invalid or expired session'}), 401  
    return jsonify({'message': f'Hello {username}, your email is {sess_email}, you are in a protected area!'}), 200


@app.route('/logout', methods=['POST'])
def logout():
    sess_email = session.get('token')
    if not sess_email:
        return jsonify({'message': 'No active session'}), 400
    else:
        # Delete the session from Redis immediately
        r.delete(f'session:{sess_email}')
        session.pop('token', None)
        return jsonify({'message': 'Logged out'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
