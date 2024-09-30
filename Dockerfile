# Используем официальный образ Python
FROM python:3.10

# Устанавливаем рабочую директорию в контейнере
WORKDIR /app

# Копируем файл requirements.txt и устанавливаем зависимости
COPY requirements.txt .

# Установка зависимостей
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все файлы проекта в контейнер
COPY . .

# Указываем порт, который будет использовать Flask
EXPOSE 5000

# Запуск приложения
CMD ["flask", "run", "--host=0.0.0.0"]
