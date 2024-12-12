import hashlib
import datetime
from flask import Flask, request, jsonify
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prod.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Замените на свой секретный ключ
#app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)  # Установите время жизни токена
db = SQLAlchemy(app)
jwt = JWTManager(app)

def generate_password_hash(password):
    password_hashed = hashlib.md5(password.encode()).hexdigest()
    return password_hashed

class Countries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    alpha2 = db.Column(db.Text, nullable=False)
    alpha3 = db.Column(db.Text, nullable=False)
    region = db.Column(db.Text, nullable=False)

class User(db.Model, UserMixin):
    __tablename__ = 'users'     

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    country_code = db.Column(db.String(2), nullable=False)
    is_public = db.Column(db.Boolean, nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    image = db.Column(db.String(255), nullable=True)

    def __init__(self, login, email, password, country_code, is_public, phone=None, image=None):
        self.login = login
        self.email = email
        self.password = password  # Hash the password
        self.country_code = country_code
        self.is_public = is_public
        self.phone = phone
        self.image = image

@app.route('/api/auth/sign-in', methods=['POST'])
def sign_in():
    data = request.json
    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({"reason": "Login and password are required"}), 400

    user = User.query.filter_by(login=login).first()

    if user and user.password == generate_password_hash(password):
        access_token = create_access_token(identity=str(user.id), expires_delta=datetime.timedelta(hours=1))
        return jsonify(token=access_token), 200
    else:
        return jsonify({"reason": "Invalid login or password"}), 401

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.json 

    required_fields = ['login', 'email', 'password', 'countryCode', 'isPublic']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({"reason": f"Missing fields {', '.join(missing_fields)} is required"}), 400
    for field in required_fields:
        if field not in data:
            return jsonify({"reason": f"{field} is required"}), 400

    print(f"The username '{data['login']}'")
    print(f"The password '{data['password']}'")

    existing_user = User.query.filter(
        (User.login == data['login']) |
        (User.email == data['email']) |
        (User.phone == data.get('phone'))
    ).first()

    if existing_user:
        return jsonify({"reason": "User with this login, email, or phone already exists"}), 409
    hash = generate_password_hash(data['password'])
    print(hash)
    new_user = User(
        login = data['login'],
        email = data['email'],
        password = hash,
        country_code = data['countryCode'],
        is_public = data['isPublic'],
        phone = data.get('phone'),
        image = data.get('image')
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/api/countries', methods=['GET'])
def get_countries():
    regions = request.args.getlist('region')

    if not regions:
        countries = Countries.query.order_by(Countries.alpha2).all()
    else:
        countries = Countries.query.filter(Countries.region.in_(regions)).order_by(Countries.alpha2).all()

    if not countries:
        return jsonify({"reason": "Invalid region"}), 400

    return jsonify([{
        "name": country.name,
        "alpha2": country.alpha2,
        "alpha3": country.alpha3,
        "region": country.region
    } for country in countries])

@app.route('/api/countries/<alpha2_code>', methods=['GET'])
def get_countries_by_alpha2_code(alpha2_code):
    countries = Countries.query.filter(Countries.alpha2.in_([alpha2_code])).all()

    if not countries:
        return jsonify({"reason": "Invalid region"}), 404

    return jsonify([{
        "name": country.name,
        "alpha2": country.alpha2,
        "alpha3": country.alpha3,
        "region": country.region
    } for country in countries][0])

@app.route('/api/ping', methods=['GET'])
def send():
    return "ok", 200

@app.route('/api/me/profile', methods=['GET', 'POST'])
@jwt_required()
def profile():
    if request.method == "GET":
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        if user:
            return jsonify({
                "login": user.login,
                "email": user.email,
                "country_code": user.country_code,
                "is_public": user.is_public,
                "phone": user.phone,
                "image": user.image
            }), 200
        else:
            return jsonify({"reason": "User not found"}), 401
    elif request.method == "POST":
        data = request.json
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        if user:
            if user.password == generate_password_hash(data["oldPassword"]):
                if len(data["newPassword"]) < 8 :
                    return jsonify({"reason": "Password must be at least 8 characters long"}), 400
                else:
                    user.password = generate_password_hash(data["newPassword"])
                    db.session.commit()
                    return jsonify({"status": "ok"}), 200
            else:
                return jsonify({"reason": "Old password is incorrect"}), 403
            
@app.route('/api/profiles/<profile_login>', methods=['GET', 'POST'])
@jwt_required()
def get_public_profile(profile_login):
    user = User.query.filter_by(login=profile_login, is_public=1).first()
    if user:
        return jsonify({
                "login": user.login,
                "email": user.email,
                "country_code": user.country_code,
                "is_public": user.is_public,
                "phone": user.phone,
                "image": user.image
        }), 200
    else:
        return jsonify({"reason": "User not found"}), 403
    





if __name__ == "__main__":
    app.run(debug=True, port=8080)