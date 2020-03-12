#!/usr/bin/env python
# coding:utf-8

import MySQLdb
import MySQLdb.cursors
from MySQLdb.constants import FIELD_TYPE

try:
    import MySQLdb.converters
except ImportError:
    _connarg('conv')

from spmo.common import Common


class Mysql(Common):
    def __init__(self, *args, **kwargs):
        self.db_hosts = kwargs.get('db_host', '127.0.0.1')
        self.db_user = kwargs.get('db_user', 'root')
        self.db_pass = kwargs.get('db_pass', '')
        self.db_name = kwargs.get('db_name', '')
        self.db_port = kwargs.get('db_port', 3306)
        if 'mysqlconf' in kwargs:
            self.mysqlconf = kwargs.get('mysqlconf', {})
        else:
            self.mysqlconf = {'db_host': self.db_hosts, 'db_user': self.db_user, 'db_pass': self.db_pass,
                              'db_name': self.db_name, 'db_port': self.db_port}
        self.convert = MySQLdb.converters.conversions.copy()
        self.convert[FIELD_TYPE.LONGLONG] = int  # long  convert into int
        self.convert[FIELD_TYPE.LONG] = int
        self.convert[FIELD_TYPE.TIMESTAMP] = str
        super(Mysql, self).__init__(*args, **kwargs)

    def open_conn(self):
        try:
            self.conn = MySQLdb.connect(host=self.mysqlconf['db_host'],
                                        user=self.mysqlconf['db_user'],
                                        passwd=self.mysqlconf['db_pass'],
                                        db=self.mysqlconf['db_name'],
                                        charset='utf8',
                                        port=int(self.mysqlconf['db_port']),
                                        conv=self.convert,
                                        use_unicode=False,
                                        cursorclass=MySQLdb.cursors.DictCursor,
                                        )
            self.cur = self.conn.cursor()
        except:
            print('Error connecting ...')

    def close_conn(self):
        self.cur.close()
        self.conn.close()

    def exec_sql(self, sql=None, rdata_type='ALL', ):
        r_data = {}
        try:
            self.open_conn()
            self.cur.execute(sql)
            self.conn.commit()
            if rdata_type == 'ALL':
                r_data = self.cur.fetchall()
            elif rdata_type == 'ONE':
                r_data = self.cur.fetchone()
            else:
                r_data = self.cur.fetchall()
        except:
            print('error !')
            self.conn.rollback()
            return {}
        finally:
            self.close_conn()

        return r_data

    def get_dblist(self, ):
        sql = 'SHOW DATABASES'
        d_list = []
        for r in self.exec_sql(sql=sql):
            if isinstance(r, tuple):
                d_list.append(r[0])
            else:
                if 'Database' in r:
                    d_list.append(r['Database'])
                else:
                    pass
        return d_list

    def get_tablelist(self, ):
        sql = 'SHOW TABLES'
        t_list = []
        for r in self.exec_sql(sql=sql):
            t_list.append(r['Tables_in_%s' % self.mysqlconf['db_name']])
        return t_list

    def selectall(self, table=''):
        sql = 'SELECT * FROM %s' % table
        return self.exec_sql(sql=sql)

    def selectone(self, table=''):
        sql = 'SELECT * FROM %s' % table
        return self.exec_sql(sql=sql, rdata_type='ONE')
