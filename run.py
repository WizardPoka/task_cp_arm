from app import create_app, db
from flask_migrate import upgrade
from t import load_data  # Импортируем функцию для загрузки данных

app = create_app()




# Запускаем приложение и вносим данные
with app.app_context():
    # Применяем миграции
    upgrade()

    # Загружаем данные из JSON
    load_data()

if __name__ == '__main__':
    app.run(debug=True)
