# -*- coding: utf-8 -*-

import sys

try:
    import cPickle as pickle
except:
    import pickle

if sys.version_info >= (2, 6, 0):
    import json as json
else:
    import simplejson as json
from datetime import date, datetime

from .common import Common
from .strings.common import b2str


class AdvEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return super(AdvEncoder, self).default(self, obj)


class DataSerialize(Common):

    def __init__(self, *args, **kwargs):
        format = kwargs.get('format', 'json')
        self.is_json_adv_encode = kwargs.get('is_json_adv_encode', True)
        if 'format' in kwargs:
            del kwargs['format']
        self.kwargs = kwargs
        if format == 'json':
            self.serialize = self.data_to_json
            self.deserialize = self.json_to_data

        if format == 'xml':
            self.serialize = self.data_to_xml
            self.deserialize = self.xml_to_data

        if format == 'pickle':
            self.serialize = self.data_to_pickle
            self.deserialize = self.pickle_to_data

    def data_to_json(self, json_d=None, **kwargs):
        akwargs = dict(self.kwargs, **kwargs)
        if sys.version_info >= (3, 0, 0):
            json_d = b2str(json_d)
        if self.is_json_adv_encode:
            json_str = json.dumps(json_d, cls=AdvEncoder, **akwargs)
        else:
            json_str = json.dumps(json_d, **akwargs)
        return json_str

    def json_to_data(self, json_str='', **kwargs):
        akwargs = dict(self.kwargs, **kwargs)
        if isinstance(json_str, bytes):
            json_str = json_str.decode('utf-8')
        json_d = json.loads(json_str, **akwargs)
        return json_d

    def data_to_pickle(self, pickle_d=None, **kwargs):
        akwargs = dict(self.kwargs, **kwargs)
        # self.DD(akwargs)
        pickle_str = pickle.dumps(pickle_d, **akwargs)
        return pickle_str

    def pickle_to_data(self, pickle_str='', **kwargs):
        akwargs = dict(self.kwargs, **kwargs)
        # self.DD(akwargs)
        pickle_d = pickle.loads(pickle_str, **akwargs)
        return pickle_d

    def data_to_xml(self):
        pass

    def xml_to_data(self):
        pass


def test():
    date_obj = datetime.now()
    ds = DataSerialize()
    print(ds.serialize(date_obj))


if __name__ == 'main':
    test()
