# -*- coding: utf-8 -*-

import sys
import collections


def trans_encode(input='', c_type='utf-8'):
    if type(input) == unicode:
        input = input.encode(c_type)
        return input
    else:
        return input

def trans_to_unicode(i_str='', c_type='utf-8'):
    '''
    转换字符串未Unicode,通用型
    '''
    if sys.version_info >= (3, 0, 0):
        unicode_string = i_str.encode('utf8')
    else:
        unicode_string = i_str.decode(sys.getfilesystemencoding()).encode('utf8')
    return unicode_string


def convert(data):
    '''
    把json 字符串转换成 python 数据类型
    convert(eval([strings]))
    :param data:
    :return:
    '''

    if isinstance(data, basestring):
        # return str(data)
        return data.encode('utf-8')
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data


def b2str(data):
    '''
    python3 中转换bytes 为 str
    :param data:
    :return:
    '''
    if isinstance(data, bytes):  return data.decode('utf-8')
    if isinstance(data, dict):   return dict(map(b2str, data.items()))
    if isinstance(data, tuple):  return map(b2str, data)
    return data


def dequote(s=''):
    '''
    去除字符串两头的 单引号和双引号
    dequote（strings）
    :param s:
    :return:
    '''
    s = s.strip()
    if (s[0] == s[-1]) and s.startswith(("'", '"')):
        return s[1:-1]
    return s


def is_contain_chinese(v_str):
    if sys.version_info < (3, 0, 0):
        v_str = v_str.decode('utf-8')
    for ch in v_str:
        if u'\u4e00' <= ch <= u'\u9fff':
            return True
    return False

    
