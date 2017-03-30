import os
import sys


class Config(object):
    SECRET_KEY = 'This key is for testing only and will not be used in production.'
    DEBUG = False
    TESTING = False
    JSON_AS_ASCII = False


class Production(Config):
    pass


class Development(Config):
    DEBUG = True


class Testing(Config):
    TESTING = True
