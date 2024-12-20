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

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.String(100), primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    likes_count = db.Column(db.Integer, default=0)
    dislikes_count = db.Column(db.Integer, default=0)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
    def __init__(self, content, author_id):
        self.content = content
        self.author_id = author_id

class PostTag(db.Model):
    __tablename__ = 'post_tags'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.String(100), db.ForeignKey('posts.id'), nullable=False)
    tag = db.Column(db.String(20), nullable=False)
    post = db.relationship('Post', backref=db.backref('tags', lazy=True))
    def __init__(self, post_id, tag):
        self.post_id = post_id
        self.tag = tag

class Countries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    alpha2 = db.Column(db.Text, nullable=False)
    alpha3 = db.Column(db.Text, nullable=False)
    region = db.Column(db.Text, nullable=False)

class Friendships(db.Model):
    __tablename__ = 'friendships'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

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
        self.password = password
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

    print(user.password, generate_password_hash(password))
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

    existing_user = User.query.filter(
        (User.login == data['login']) |
        (User.email == data['email']) |
        (User.phone == data.get('phone'))
    ).first()

    if existing_user:
        return jsonify({"reason": "User with this login, email, or phone already exists"}), 409
    hash = generate_password_hash(data['password'])
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
    print("Login is", new_user.login)
    print(jsonify({"profile": {"login": new_user.login, "email": new_user.email, "countryCode": new_user.country_code, "isPublic": new_user.is_public, "phone": new_user.phone, "image": new_user.image}}))
    return jsonify({"profile": {"login": new_user.login, "email": new_user.email, "countryCode": new_user.country_code, "isPublic": new_user.is_public, "phone": new_user.phone, "image": new_user.image}}), 201

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

@app.route('/api/me/profile', methods=['GET', 'PATCH'])
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
    elif request.method == "PATCH":
        try:
            data = request.json.pop('password')
        except:
            data = request.json
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        if user:
            if 'login' in data:
                if not isinstance(data['login'], str) or len(data['login']) < 3 or len(data['login']) > 80:
                    return jsonify({"reason": "Login must be a string with a length between 3 and 80 characters"}), 400
                user.login = data['login']
            if 'email' in data:
                if not isinstance(data['email'], str) or len(data['email']) < 5 or len(data['email']) > 120:
                    return jsonify({"reason": "Email must be a string with a length between 5 and 120 characters"}), 400
                existing_user = User.query.filter_by(email=data['email']).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({"reason": "Email already in use"}), 400
                user.email = data['email']
            if 'countryCode' in data:
                country = Countries.query.filter_by(alpha2=data['countryCode']).first()
                if not country:
                    return jsonify({"reason": "Country with the specified code not found"}), 400
                user.country_code = data['countryCode']
            if 'isPublic' in data:
                if not isinstance(data['isPublic'], bool):
                    return jsonify({"reason": "IsPublic must be a boolean"}), 400
                user.is_public = data['isPublic']
            if 'phone' in data:
                if not isinstance(data['phone'], str) or len(data['phone']) < 5 or len(data['phone']) > 15:
                    return jsonify({"reason": "Phone must be a string with a length between 5 and 15 characters"}), 400
                existing_user = User.query.filter_by(phone=data['phone']).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({"reason": "Phone already in use"}), 400
                user.phone = data['phone']
            if 'image' in data:
                if not isinstance(data['image'], str) or len(data['image']) > 255:
                    return jsonify({"reason": "Image link must be a string with a length not exceeding 255 characters"}), 400
                user.image = data['image']
            db.session.commit()
            return jsonify({
                "login": user.login,
                "email": user.email,
                "country_code": user.country_code,
                "is_public": user.is_public,
                "phone": user.phone,
                "image": user.image
            }), 200
                            
        

@app.route("/api/me/updatePassword", methods=["POST"])
@jwt_required()
def update_password():
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
    
@app.route('/api/profiles/', methods=['GET'])
@jwt_required()
def no_login():
    return jsonify({"reason": "You must be logged in to access this endpoint"}), 403
    


@app.route('/api/friends', methods=['GET'])
@jwt_required()
def friends_list():
    user_id = int(get_jwt_identity())
    limit = request.args.get('limit', default=10, type=int)
    offset = request.args.get('offset', default=0, type=int)

    friends = db.session.query(User).join(Friendships, Friendships.friend_id == User.id).filter(Friendships.user_id == user_id).order_by(Friendships.created_at.desc()).offset(offset).limit(limit).all()

    if not friends:
        return jsonify([]), 200

    friends_list = [{
        "login": friend.login,
        "addedAt": friend.created_at.isoformat()  
    } for friend in friends]

    return jsonify(friends_list), 200

@app.route('/api/friends/add', methods=['POST'])
@jwt_required()
def friends_add():
    data = request.json
    login = data.get('login')

    if not login:
        return jsonify({"reason": "Login is required"}), 400

    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.login == login:
        return jsonify({"status": "ok"}), 200

    friend = User.query.filter_by(login=login).first()
    if not friend:
        return jsonify({"reason": "User not found"}), 404

    existing_friendship = Friendships.query.filter_by(user_id=current_user_id, friend_id=friend.id).first()
    if existing_friendship:
        return jsonify({"status": "ok"}), 200

    new_friendship = Friendships(user_id=current_user_id, friend_id=friend.id)
    db.session.add(new_friendship)
    db.session.commit()

    return jsonify({"status": "ok"}), 200

@app.route('/api/friends/remove', methods=['POST'])
@jwt_required()
def friends_remove():
    data = request.json
    login = data.get('login')

    if not login:
        return jsonify({"reason": "Login is required"}), 400

    current_user_id = get_jwt_identity()
    friend = User.query.filter_by(login=login).first()
    if not friend:
        return jsonify({"reason": "User not found"}), 404

    friendship = Friendships.query.filter_by(user_id=current_user_id, friend_id=friend.id).first()
    if not friendship:
        return jsonify({"status": "ok"}), 200

    db.session.delete(friendship)
    db.session.commit()

    return jsonify({"status": "ok"}), 200

@app.route("/api/posts/new", methods=["POST"])
@jwt_required()
def posts_new():
    data = request.json
    content = data["content"]
    tags = data["tags"]

    if not content or not tags :
        return jsonify({"reason": "Content and tags are required"}), 400
    current_user_id = get_jwt_identity()




if __name__ == "__main__":
    app.run(debug=True, port=8080)