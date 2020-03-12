# -*- coding:utf-8 -*-

import uuid
import pprint
from datetime import datetime


def DD(vars):
    pprint.pprint(vars)


def get_uuid():
    uuid_1 = uuid.uuid1()
    uuid_4 = uuid.uuid4()
    return '%s-%s' % (uuid_1, uuid_4)


def get_now_timestamp():
    return datetime.now().strftime('%Y%m%d%H%M%S')


class Common(object):

    def __init__(self, *args, **kwargs):
        pass

    def DD(self, vars):
        DD(vars)

    def get_uuid(self):
        return get_uuid()

    def get_create_date(self):
        return get_now_timestamp()
