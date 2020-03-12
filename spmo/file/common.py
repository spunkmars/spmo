# -*- coding:utf-8 -*-

import os
import sys
import time
import pprint
import copy
import re
import codecs
import posixpath

from spmo.common import Common


def handle_file(f, file_path):
    with open(file_path, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return file_path


def convert_ntpath_to_unixpath(winpath=None):
    if winpath is not None:
        # return (posixpath.join(*('%r' % winpath).split(os.sep))).replace('\'', '').replace('^u', '')
        r_list = ('%s' % winpath).replace("'", '').split(os.sep)
        if r_list[0] == '':
            return os.sep + posixpath.join(*r_list)
        else:
            return posixpath.join(*r_list)


class File(Common):
    def __init__(self, *args, **kwargs):
        self.encoding = kwargs.get('encoding', 'utf-8')
        self.line_break = kwargs.get('line_break', 'CRLF')
        if self.line_break == 'CRLF':
            self.line_break_char = '\r\n'
        elif self.line_break == 'LF':
            self.line_break_char = '\n'
        else:
            self.line_break_char = '\n'
        super(File, self).__init__(*args, **kwargs)

    def read_file(self, rfile=None):
        file_content = ''
        fileHeadle = None
        rfile = convert_ntpath_to_unixpath(rfile)
        try:
            fileHeadle = codecs.open(rfile, 'r', encoding=self.encoding)
            file_content = ''.join(fileHeadle.readlines())
        except:
            print('occur error: read file [%s]' % rfile)
        finally:
            if fileHeadle is not None:
                fileHeadle.close()
        return file_content

    def write_file(self, wfile=None, file_content=None):
        if file_content is None:
            return False
        file_content = map(lambda line: '%s%s' % (line, self.line_break_char), [l for l in file_content])
        wfile = convert_ntpath_to_unixpath(wfile)
        fileHeadle = None
        try:
            fileHeadle = codecs.open(wfile, 'w', self.encoding)
            if (sys.version_info >= (3, 0, 0) and isinstance(file_content, map)) or isinstance(file_content, list):
                fileHeadle.writelines(file_content)
            else:
                fileHeadle.write(file_content)
        except:
            print('occur error: write file [%s]' % wfile)
        finally:
            if fileHeadle is not None:
                fileHeadle.close()
