# routes.py
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required, create_access_token
from app.models import db, User, Document, DocumentType, GenderType, UserType
from sqlalchemy.exc import IntegrityError
import base64
import json
from datetime import datetime

bp = Blueprint('routes', __name__)

@bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        description: User registration details
        required: true
        schema:
          type: object
          required:
            - login
            - password
            - last_name
            - first_name
            - gender
            - type_id
          properties:
            login:
              type: string
              example: "user1"
            password:
              type: string
              example: "password123"
            last_name:
              type: string
              example: "Иванов"
            first_name:
              type: string
              example: "Иван"
            patr_name:
              type: string
              example: "Иванович"
            gender:
              type: integer
              example: 1
            type_id:
              type: integer
              example: 2
    responses:
      201:
        description: User registered successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: "User registered successfully"
      400:
        description: Missing required fields or user already exists
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Login and password are required"
    """
    data = request.json
    required_fields = ['login', 'password', 'last_name', 'first_name', 'gender', 'type_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Проверка уникальности логина
    if User.query.filter_by(login=data['login']).first():
        return jsonify({'error': 'User with this login already exists'}), 400

    # Получение пола и типа пользователя
    gender = GenderType.query.get(data['gender'])
    user_type = UserType.query.get(data['type_id'])

    if not gender or not user_type:
        return jsonify({'error': 'Invalid gender or user type'}), 400

    # Кодирование пароля в base64
    encoded_password = base64.b64encode(data['password'].encode('utf-8')).decode('utf-8')

    user = User(
        last_name=data['last_name'],
        first_name=data['first_name'],
        patr_name=data.get('patr_name'),
        gender_id=gender.id,
        type_id=user_type.id,
        login=data['login'],
        password=encoded_password,
        create_datetime=datetime.utcnow()
    )
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'User with this login already exists'}), 400
    
    return jsonify({'message': 'User registered successfully'}), 201

@bp.route('/login', methods=['POST'])
def login():
    """
    User login to obtain JWT token.
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        description: User login credentials
        required: true
        schema:
          type: object
          required:
            - login
            - password
          properties:
            login:
              type: string
              example: "user1"
            password:
              type: string
              example: "password123"
    responses:
      200:
        description: Successful login with JWT token
        schema:
          type: object
          properties:
            access_token:
              type: string
              example: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      401:
        description: Invalid credentials
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Invalid credentials"
    """
    data = request.json
    user = User.query.filter_by(login=data.get('login')).first()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Декодирование пароля из base64 и проверка
    try:
        decoded_password = base64.b64decode(user.password).decode('utf-8')
    except Exception:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if decoded_password != data.get('password'):
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

@bp.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    """
    Get information about the authenticated user.
    ---
    tags:
      - User
    security:
      - Bearer: []
    responses:
      200:
        description: User information
        schema:
          type: object
          properties:
            id:
              type: integer
              example: 1
            login:
              type: string
              example: "user1"
            documents:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                    example: 18382434
                  data:
                    type: object
      401:
        description: Unauthorized access
        schema:
          type: object
          properties:
            msg:
              type: string
              example: "Missing Authorization Header"
    """
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    user_info = {
        'id': user.id,
        'login': user.login,
        'documents': [json.loads(doc.data) for doc in user.documents]
    }
    return jsonify(user_info), 200

@bp.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    """
    Get information about all users (admin only).
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    responses:
      200:
        description: List of all users
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
                example: 1
              login:
                type: string
                example: "user1"
              documents:
                type: array
                items:
                  type: object
                  properties:
                    id:
                      type: integer
                      example: 18382434
                    data:
                      type: object
      401:
        description: Unauthorized access
        schema:
          type: object
          properties:
            msg:
              type: string
              example: "Missing Authorization Header"
      403:
        description: Forbidden access (not an admin)
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Admin privileges required"
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or user.type_id != 1:  # Предполагается, что type_id=1 — админ
        return jsonify({'error': 'Admin privileges required'}), 403

    users = User.query.all()
    result = []
    for user in users:
        result.append({
            'id': user.id,
            'login': user.login,
            'documents': [json.loads(doc.data) for doc in user.documents]
        })
    return jsonify(result), 200
