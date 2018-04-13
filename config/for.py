import os
import sys


class Config(object):
    SECRET_KEY = 'This key is for testing only and will not be used in production.'
    DEBUG = False
    TESTING = False
    JSON_AS_ASCII = False
    WEBHOOK_SECRET = 'This is another key for testing only'


class Production(Config):
    pass


class Development(Config):
    DEBUG = True


class Testing(Config):
    TESTING = True
