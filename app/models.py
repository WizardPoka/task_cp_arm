# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt

db = SQLAlchemy()

class Address(db.Model):
    __tablename__ = 'addresses'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    value = db.Column(db.String(1024), nullable=False)
    guid = db.Column(db.String(255), nullable=False)
    
    create_datetime = db.Column(db.DateTime, default=datetime.utcnow)
    modify_datetime = db.Column(db.DateTime, onupdate=datetime.utcnow)
    deleted = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref='address', lazy=True)

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(255), nullable=False)
    patr_name = db.Column(db.String(255))
    gender_id = db.Column(db.Integer, db.ForeignKey('gender_types.id'))
    type_id = db.Column(db.Integer, db.ForeignKey('user_types.id'))
    login = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    create_datetime = db.Column(db.DateTime, default=datetime.utcnow)
    modify_datetime = db.Column(db.DateTime, onupdate=datetime.utcnow)
    deleted = db.Column(db.Integer, default=0)
    
    documents = db.relationship('Document', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class DocumentType(db.Model):
    __tablename__ = 'document_types'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    create_datetime = db.Column(db.DateTime, default=datetime.utcnow)
    modify_datetime = db.Column(db.DateTime, onupdate=datetime.utcnow)
    deleted = db.Column(db.Integer, default=0)
    
    documents = db.relationship('Document', backref='type', lazy=True)

class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    type_id = db.Column(db.Integer, db.ForeignKey('document_types.id'))
    data = db.Column(db.Text, nullable=False)
    create_datetime = db.Column(db.DateTime, default=datetime.utcnow)
    modify_datetime = db.Column(db.DateTime, onupdate=datetime.utcnow)
    deleted = db.Column(db.Integer, default=0)

class GenderType(db.Model):
    __tablename__ = 'gender_types'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    create_datetime = db.Column(db.DateTime, default=datetime.utcnow)
    modify_datetime = db.Column(db.DateTime, onupdate=datetime.utcnow)
    deleted = db.Column(db.Integer, default=0)
    
class UserType(db.Model):
    __tablename__ = 'user_types'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    create_datetime = db.Column(db.DateTime, default=datetime.utcnow)
    modify_datetime = db.Column(db.DateTime, onupdate=datetime.utcnow)
    deleted = db.Column(db.Integer, default=0)
