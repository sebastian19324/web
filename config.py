import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'clave-secreta-para-desarrollo'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:Sarajuliana123@localhost:5432/Abokin_DB'
    SQLALCHEMY_TRACK_MODIFICATIONS = False