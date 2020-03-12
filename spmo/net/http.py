# -*- coding: utf-8 -*-

import sys
import copy
import os
import re
import ssl

try:
    import http.cookiejar as cookielib
    from http.cookiejar import Cookie
except ImportError:
    import cookielib

if sys.version_info >= (3, 0, 0):
    import http.client as httplib
    from urllib.parse import urlparse
    from urllib.parse import urlencode
    from urllib.parse import quote
else:
    import httplib
    from urlparse import urlparse
    from urllib import urlencode

import urllib.request
import urllib.error

from spmo.common import Common
from spmo.data_serialize import DataSerialize


def parse_uri(uri=None):
    uri_h = None
    if sys.version_info >= (2, 5, 0):
        url_h = urlparse(uri)
        url_scheme = url_h.scheme
        url_hostname = url_h.hostname
        url_port = url_h.port
        url_path = url_h.path
        url_query = url_h.query
        url_fragment = url_h.fragment
        url_params = url_h.params
        url_netloc = url_h.netloc
        uri_h = {'scheme': url_scheme,
                 'hostname': url_hostname,
                 'port': url_port,
                 'path': re.sub(r'/{2,}', '/', url_path),  # 替换连续多个/ 为单个。
                 'query': url_query,
                 'fragment': url_fragment,
                 'params': url_params,
                 'netloc': url_netloc,
                 }
    else:
        url_h = urlparse(uri)
        url_scheme = url_h[0]
        host_a = url_h[1].split(':')
        url_hostname = host_a[0]
        if len(host_a) == 2:
            url_port = host_a[1]
        else:
            url_port = None
        url_path = url_h[2]
        uri_h = {'scheme': url_scheme,
                 'hostname': url_hostname,
                 'port': url_port,
                 'path': re.sub(r'/{2,}', '/', url_path),  # 替换连续多个/ 为单个。
                 }
    return uri_h


def join_uri(uri_h={}):
    # co.DD(uri_h)
    uri = ''
    if 'scheme' in uri_h:
        uri = '%s' % uri_h['scheme']
    else:
        if 'port' in uri_h:
            if uri_h['port'] == 443:
                uri = 'https'
            else:
                uri = 'http'
        else:
            uri = 'http'
    if 'hostname' in uri_h:
        uri = '%s://%s' % (uri, uri_h['hostname'])
        if 'port' in uri_h:
            uri = '%s:%s' % (uri, str(uri_h['port']))
        else:
            uri = '%s:%s' % (uri, '80')
    else:
        if 'netloc' in uri_h:
            uri = '%s://%s' % (uri, uri_h['netloc'])
        else:
            raise Exception('Can not find hostname or netloc !')

    if 'path' in uri_h:
        uri = '%s/%s' % (uri, str(uri_h['path']))
    else:
        uri = '%s%s' % (uri, '/')
    if 'query' in uri_h:
        uri = '%s?%s' % (uri, str(uri_h['query']))
    return uri


def dict_from_cookiejar(cj_ins=None):
    # co.DD(cj_ins)
    if cj_ins and isinstance(cj_ins, cookielib.CookieJar):
        return {i.name: i.value for i in list(cj_ins)}
    else:
        return {}


def set_cookie(cj_ins=None, domain=None, cookies={}):
    if cj_ins and isinstance(cj_ins, cookielib.CookieJar):
        for ck_name, ck_val in cookies.items():
            cj_ins.set_cookie(make_simple_cookie(domain=domain, name=ck_name, value=ck_val))


def dict_from_httpmessage(hm_ins=None):
    if hm_ins and isinstance(hm_ins, httplib.HTTPMessage):
        return {hl[0]: hl[1] for hl in hm_ins.items()}
    else:
        return {}


def make_simple_cookie(domain=None, name=None, value=None):
    ck = cookielib.Cookie(
        version=0, name=str(name), value=str(value),
        port=None, port_specified=False,
        domain=domain,
        domain_specified=True, domain_initial_dot=False,
        path="/", path_specified=True, secure=False,
        expires=None, discard=True,
        comment=None, comment_url=None,
        rest={"HttpOnly": None}, rfc2109=False)
    return ck


class Http2(Common):
    def __init__(self, *args, **kwargs):
        self.is_debug = kwargs.get('is_debug', False)
        self.data_format = kwargs.get('data_format', 'json')
        self.ds = DataSerialize(format=self.data_format)
        error_info = {'error_reason': '', 'error_code': 0}
        self.error_info = kwargs.get('error_info', error_info)
        self.is_data_serialize = kwargs.get('is_data_serialize', 0)
        if 'is_data_serialize' in kwargs:
            self.is_data_serialize = kwargs.get('is_data_serialize', 0)
            self.is_send_data_serialize = self.is_data_serialize
            self.is_rec_data_deserialize = self.is_data_serialize
        else:
            self.is_send_data_serialize = kwargs.get('is_send_data_serialize', 0)
            self.is_rec_data_deserialize = kwargs.get('is_rec_data_deserialize', 0)
        headers = {"Content-type": "application/json", "Accept": "text/plain"}
        self.headers = kwargs.get('headers', headers)
        self.cj_ins = cookielib.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj_ins))
        urllib.request.install_opener(self.opener)
        self.cookies = {}
        self.disable_ssl_check = kwargs.get('disable_ssl_check', False)

    def set_cookie(self, request=None, domain=None, cookies={}):
        if domain is not None and domain != '':
            if len(cookies) > 0:
                set_cookie(self.cj_ins, domain=domain, cookies=cookies)
            elif len(self.cookies) > 0:
                set_cookie(self.cj_ins, domain=domain, cookies=self.cookies)
        if request is not None:
            self.cj_ins.add_cookie_header(request)

    def reset_error_info(self):
        self.error_info = {'error_reason': '', 'error_code': 0}

    def set_http_headers(self, headers={}):
        self.headers = headers

    def update_http_headers(self, headers={}):
        self.headers.update(headers)

    def connect(self, uri_h=None, content=None, api_url=None, http_method='GET', cookies={}):
        api_url_scheme = uri_h['scheme']
        api_url_hostname = uri_h['hostname']
        api_url_port = uri_h['port']
        api_url_path = uri_h['path']
        api_url_params = uri_h['params']
        api_url_query = uri_h['query'].lstrip(' ').rstrip(' ')
        url = join_uri(uri_h)
        # if self.cj_ins is None or isinstance(self.cj_ins, cookielib.CookieJar) is False:
        #     print('get new cookie ins...')
        #     self.cj_ins = cookielib.CookieJar()

        if http_method in ['GET']:
            # # 确保GET方法采用HTTP协议标准用法，当有query时，加入url中
            if api_url_query is not None and api_url_query != '':
                if api_url_path == '' or api_url_path is None:
                    api_url_path = '/?' + api_url_query
                else:
                    if self.is_debug:
                        print('api_url_query:"%s"' % api_url_query)
                    api_url_path = api_url_path + '?' + api_url_query
        uri_h2 = copy.copy(uri_h)
        uri_h2.update({'query': api_url_query})
        # url = join_uri()
        url = join_uri(uri_h2)
        if content is not None:
            if type(content) != bytes:
                request_data = content.encode('utf-8')
                # request_data = bytes(content, 'utf-8')
            else:
                request_data = content
        else:
            request_data = b''
        req = urllib.request.Request(url=url, headers=self.headers, data=request_data,
                                     method=http_method)

        self.set_cookie(request=req, domain=uri_h['hostname'], cookies=cookies)
        response_status = {}
        response_data = {}
        response = None
        if self.is_debug: self.DD(req.header_items())
        try:
            if self.disable_ssl_check == True:
                response = urllib.request.urlopen(req, context=ssl._create_unverified_context())
            else:
                response = urllib.request.urlopen(req)
            # response = self.opener.open(req)
            response_status['code'] = response.code
            response_status['response_headers'] = dict_from_httpmessage(response.headers)
            response_status['requset_headers'] = req.header_items()
            response_status['msg'] = response.msg
            response_status['reason'] = response.msg
            response_data = response.read().decode("utf8")
        except urllib.error.HTTPError as err:
            response_status['code'] = err.code
            response_status['reason'] = err.reason
            response_status['response_headers'] = dict_from_httpmessage(err.headers)
            response_status['requset_headers'] = req.header_items()
            response_status['msg'] = 'ERROR'
            response_data = err.fp.read().decode("utf8")
        except urllib.error.URLError as err:
            response_status['reason'] = err.reason
            response_status['msg'] = 'ERROR'
        finally:
            if response and hasattr(response, 'close'):
                response.close()
        response_cookie = dict_from_cookiejar(self.cj_ins)
        return response_data, response_status, response_cookie

    def http_connect(self, content=None, api_url=None, http_method='GET', cookies={}):
        self.error_code = 0
        self.error_reason = ''
        self.reset_error_info()

        data = None
        error = None
        conn = None
        response = None
        uri_h = parse_uri(uri=api_url)
        if self.is_debug: print('api_url:%s, content:%s' % (api_url, content))
        response_data, response_status, response_cookie = self.connect(uri_h=uri_h, content=content, api_url=api_url,
                                                                       http_method=http_method, cookies=cookies)
        # self.DD(response_status)
        if response_status['code'] in (301, 302, 304, 307):
            new_url = response.getheader("Location")
            new_uri_h = parse_uri(uri=new_url)
            new_uri_h = dict(uri_h, **new_uri_h)
            new_uri_h['query'] = uri_h['query']
            response_data, response_status, response_cookie = self.connect(uri_h=new_uri_h, content=content,
                                                                           api_url=new_url,
                                                                           http_method=http_method, cookies=cookies)

        if self.is_debug: print('stats:%s, reason:%s' % (response_status['code'], response_status['reason']))
        if self.is_debug: self.DD(response_status['response_headers'])
        if response_status['code'] in (200, 201, 202) and response_status['reason'] in ('OK', 'Accepted'):
            return response_data, response_status, response_cookie
        else:
            if response_status['code'] == 401:
                self.error_info['error_code'] = 2
            else:
                self.error_info['error_code'] = 1
            self.error_info['error_reason'] = 'connect %s error: status>%s  reason> %s' % (
                api_url, response_status['code'], response_status['reason'])
            return response_data, response_status, response_cookie

    def api_connect(self, api_url=None, params=None, http_method='GET', cookies={}):
        if self.is_debug: self.DD(params)
        if http_method.upper() in ['GET', 'HEAD']:
            # 确保GET 请求使用HTTP协议标准用法，参数放入url中，而不是放入body中。
            params = urlencode(params)
            params = params.lstrip(' ').rstrip(' ')
            if params is not None and params != '':
                api_url = api_url + '?' + params
            content = None
        elif http_method.upper() == 'POST':
            if params is not None:
                if self.is_send_data_serialize == 1 and isinstance(params, dict):
                    params = self.ds.serialize(params)
                else:
                    if 'Content-Type' in self.headers and \
                            self.headers['Content-Type'] == 'application/x-www-form-urlencoded':
                        # 只有在请求头中Content-Type明确使用urlencode，才对参数进行urlencode
                        params = urlencode(params)
            content = params
        else:
            content = params
        # if self.is_debug: print('api_url = %s' % api_url)
        data, response_status, response_cookie = self.http_connect(content=content, api_url=api_url,
                                                                   http_method=http_method, cookies=cookies)
        if self.is_debug: self.DD(data)
        if self.is_debug: self.DD(self.error_info)
        if self.error_info['error_code'] == 0 and self.is_rec_data_deserialize == 1:
            if self.is_debug: self.DD(response_status)
            if data is not None and data != '' and response_status['response_headers']['Content-Type'].lower().find(
                    'application/json') >= 0:
                data = self.ds.deserialize(data)
        return data, response_status, response_cookie


class Http(Common):

    def __init__(self, *args, **kwargs):
        self.is_debug = kwargs.get('is_debug', False)
        self.data_format = kwargs.get('data_format', 'json')
        self.ds = DataSerialize(format=self.data_format)
        error_info = {'error_reason': '', 'error_code': 0}
        self.error_info = kwargs.get('error_info', error_info)
        self.is_data_serialize = kwargs.get('is_data_serialize', 0)
        if 'is_data_serialize' in kwargs:
            self.is_data_serialize = kwargs.get('is_data_serialize', 0)
            self.is_send_data_serialize = self.is_data_serialize
            self.is_rec_data_deserialize = self.is_data_serialize
        else:
            self.is_send_data_serialize = kwargs.get('is_send_data_serialize', 0)
            self.is_rec_data_deserialize = kwargs.get('is_rec_data_deserialize', 0)
        headers = {"Content-type": "application/json", "Accept": "text/plain"}
        self.headers = kwargs.get('headers', headers)

    def reset_error_info(self):
        self.error_info = {'error_reason': '', 'error_code': 0}

    def set_http_headers(self, headers={}):
        self.headers = headers

    def update_http_headers(self, headers={}):
        self.headers.update(headers)

    def connect(self, uri_h=None, content=None, api_url=None, http_method=None, conn=None, response=None):
        api_url_scheme = uri_h['scheme']
        api_url_hostname = uri_h['hostname']
        api_url_port = uri_h['port']
        api_url_path = uri_h['path']
        api_url_params = uri_h['params']
        api_url_query = uri_h['query'].lstrip(' ').rstrip(' ')
        if api_url_scheme == 'https':
            conn = httplib.HTTPSConnection(api_url_hostname, api_url_port)
        elif api_url_scheme == 'http':
            conn = httplib.HTTPConnection(api_url_hostname, api_url_port)
        else:
            self.error_code = 1
            self.error_reason = 'invalid url !'
        # print 'method: %s,   url:%s' % (http_method,  api_url_path)

        if http_method == 'GET':
            # # 确保GET方法采用HTTP协议标准用法，当有query时，加入url中
            if api_url_query is not None and api_url_query != '':
                if api_url_path == '' or api_url_path is None:
                    api_url_path = '/?' + api_url_query
                else:
                    if self.is_debug:
                        print('api_url_query:"%s"' % api_url_query)
                    api_url_path = api_url_path + '?' + api_url_query
        try:
            if self.is_debug: print('api_url_path: %s' % api_url_path)
            if 'Authorization' in self.headers:
                if self.is_debug: print('auth headers: %s' % self.headers['Authorization'])

            if hasattr(conn, 'request'):
                conn.request(http_method, api_url_path, content, self.headers, )
                response = conn.getresponse()
                response_data = response.read()

            else:
                response_data = None
        finally:
            if hasattr(conn, 'close'):
                conn.close()
        return response, response_data

    def http_connect(self, content=None, api_url=None, http_method='POST'):
        self.error_code = 0
        self.error_reason = ''
        self.reset_error_info()

        data = None
        error = None
        conn = None
        response = None
        uri_h = parse_uri(uri=api_url)
        if self.is_debug: print('api_url:%s, content:%s' % (api_url, content))
        (response, response_data) = self.connect(uri_h=uri_h, content=content, api_url=api_url, http_method=http_method)
        if response.status in (301, 302, 304, 307):
            new_url = response.getheader("Location")
            new_uri_h = parse_uri(uri=new_url)
            new_uri_h = dict(uri_h, **new_uri_h)
            new_uri_h['query'] = uri_h['query']
            (response, response_data) = self.connect(uri_h=new_uri_h, content=content, api_url=new_url,
                                                     http_method=http_method)

        if self.is_debug: print('stats:%s, reason:%s' % (response.status, response.reason))
        if self.is_debug: self.DD(response.getheaders())
        if response.status in (200, 202) and response.reason in ('OK', 'Accepted'):
            return response_data
        else:
            if response.status == 401:
                self.error_info['error_code'] = 2
            else:
                self.error_info['error_code'] = 1
            self.error_info['error_reason'] = 'connect %s error: status>%s  reason> %s' % (
                api_url, response.status, response.reason)

    def api_connect(self, params=None, api_url=None, http_method='POST'):
        self.error_code = 0
        self.error_reason = ''
        self.reset_error_info()
        data = None
        error = None

        if http_method.upper() == 'GET':
            # 确保GET 请求使用HTTP协议标准用法，参数放入url中，而不是放入body中。
            params = urlencode(params)
            params = params.lstrip(' ').rstrip(' ')
            if params is not None and params != '':
                api_url = api_url + '?' + params
            content = None
        elif http_method.upper() == 'POST':
            if params is not None:
                if self.is_send_data_serialize == 1 and isinstance(params, dict):
                    params = self.ds.serialize(params)
                else:
                    if 'Content-Type' in self.headers and \
                            self.headers['Content-Type'] == 'application/x-www-form-urlencoded':
                        # 只有在请求头中Content-Type明确使用urlencode，才对参数进行urlencode
                        params = urlencode(params)
            content = params
        else:
            pass
        if self.is_debug: print('api_url = %s' % api_url)
        data = self.http_connect(content=content, api_url=api_url, http_method=http_method)
        if self.is_debug: self.DD(data)
        if self.is_debug: self.DD(self.error_info)
        if self.error_info['error_code'] == 0 and self.is_rec_data_deserialize == 1:
            data = self.ds.deserialize(data)
        return data
