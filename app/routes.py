# routes.py
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required, create_access_token
from app.models import db, User, Document, DocumentType, GenderType, UserType, Address
from sqlalchemy.exc import IntegrityError
import base64
import json
from datetime import datetime

bp = Blueprint('routes', __name__)

@bp.route('/receive_package', methods=['POST'])
@jwt_required()
def receive_package():
    """
    Endpoint for receiving a package and saving user documents to the database.
    ---
    tags:
      - Documents
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        description: Package data
        required: true
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
                example: 80087332
              referralGUID:
                type: string
                example: "F234FG244422FFFFF4:232RFS"
              referralDate:
                type: string
                format: date-time
                example: "2024-01-23T18:55:02"
              Data:
                type: array
                items:
                  type: object
                  properties:
                    Sender:
                      type: object
                      properties:
                        Organization:
                          type: object
                          properties:
                            oid:
                              type: string
                              example: "1.2.5.23.543.1234.18972"
                            fullName:
                              type: string
                              example: "СП.АРМ"
                    Users:
                      type: array
                      items:
                        type: object
                        properties:
                          id:
                            type: integer
                            example: 1504926
                          lastName:
                            type: string
                            example: "Иванова"
                          firstName:
                            type: string
                            example: "Екатерина"
                          patrName:
                            type: string
                            example: "Петровна"
                          birthDate:
                            type: string
                            format: date
                            example: "1996-06-08"
                          sex:
                            type: string
                            example: "2"
                          phoneNumber:
                            type: string
                            example: "9999999999"
                          snils:
                            type: string
                            example: "12495797018"
                          inn:
                            type: string
                            example: "027801597819"
                          socStatus_id:
                            type: string
                            example: "102"
                          Address:
                            type: object
                            properties:
                              id:
                                type: string
                                example: "11337703"
                              value:
                                type: string
                                example: "450015, РОССИЯ, БАШКОРТОСТАН РЕСП..."
                              guid:
                                type: string
                                example: "8479A314-A179-4874-A8FD-AC7CED2BCEE5"
                          Documents:
                            type: array
                            items:
                              type: object
                              properties:
                                id:
                                  type: string
                                  example: "18382434"
                                documentType_id:
                                  type: integer
                                  example: 2
                                documentType_Name:
                                  type: string
                                  example: "Полис ОМС"
                                series:
                                  type: string
                                  example: "12433"
                                number:
                                  type: string
                                  example: "0253310891000710"
                                beginDate:
                                  type: string
                                  format: date
                                  example: "2021-12-14"
    responses:
      201:
        description: Package processed successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: "Package received and processed"
      400:
        description: Bad request
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Invalid data format"
    """
    data = request.json
    if not isinstance(data, list):
        return jsonify({'error': 'Invalid data format'}), 400

    for package in data:
        for user_data in package['Data'][0]['Users']:
            # Check if the user already exists by login (unique constraint)
            user = User.query.filter_by(login=user_data['Credentials']['username']).first()

            if not user:
                # Only create a new user if the login does not already exist
                try:
                    user = User(
                        id=user_data['id'],
                        last_name=user_data['lastName'],
                        first_name=user_data['firstName'],
                        patr_name=user_data.get('patrName'),
                        gender_id=int(user_data['sex']),
                        login=user_data['Credentials']['username'],
                        password=user_data['Credentials']['pass'],
                    )
                    db.session.add(user)
                except IntegrityError:
                    db.session.rollback()
                    return jsonify({'error': 'User with this login already exists'}), 400

            # Save user's address
            if 'Address' in user_data:
                address_data = user_data['Address']
                address = Address(
                    user=user,
                    value=address_data['value'],
                    guid=address_data['guid']
                )
                db.session.add(address)

            # Save user's documents
            if 'Documents' in user_data:
                for doc_data in user_data['Documents']:
                    document = Document(
                        user=user,
                        type_id=doc_data['documentType_id'],
                        data=json.dumps(doc_data)
                    )
                    db.session.add(document)

    db.session.commit()
    return jsonify({'message': 'Package received and processed'}), 201


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

