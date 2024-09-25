from app.models import db, User, Document, DocumentType, GenderType, UserType
import json
from datetime import datetime

def load_data():
    # Проверка наличия полов в таблице и добавление, если их нет
    if GenderType.query.count() == 0:
        male = GenderType(name='Мужской')
        female = GenderType(name='Женский')
        db.session.add(male)
        db.session.add(female)
        db.session.commit()

    # Проверка наличия типов пользователей в таблице и добавление, если их нет
    if UserType.query.count() == 0:
        admin_type = UserType(name='Администратор')
        user_type = UserType(name='Пользователь')
        db.session.add(admin_type)
        db.session.add(user_type)
        db.session.commit()

    # Загрузка данных из JSON файла
    with open('example.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    for item in data:
        for user_data in item['Data'][0]['Users']:
            # Получение пола пользователя
            gender = GenderType.query.filter_by(name='Женский' if user_data['sex'] == '2' else 'Мужской').first()

            # Получение типа пользователя
            user_type = UserType.query.filter_by(name='Пользователь').first()

            # Проверка, существует ли пользователь с таким логином
            existing_user = User.query.filter_by(login=user_data['Credentials']['username']).first()

            if existing_user:
                print(f"Пользователь с логином {user_data['Credentials']['username']} уже существует. Пропуск.")
                continue

            # Создание пользователя
            user = User(
                last_name=user_data['lastName'],
                first_name=user_data['firstName'],
                patr_name=user_data.get('patrName'),
                gender_id=gender.id,
                type_id=user_type.id,
                login=user_data['Credentials']['username'],
                password=user_data['Credentials']['pass'],
                create_datetime=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()

            # Добавление документов пользователя
            for document_data in user_data['Documents']:
                document_type = DocumentType.query.filter_by(name=document_data['documentType_Name']).first()

                if not document_type:
                    document_type = DocumentType(name=document_data['documentType_Name'])
                    db.session.add(document_type)
                    db.session.commit()

                document = Document(
                    user_id=user.id,
                    type_id=document_type.id,
                    data=json.dumps(document_data),
                    create_datetime=datetime.utcnow()
                )
                db.session.add(document)
            db.session.commit()
