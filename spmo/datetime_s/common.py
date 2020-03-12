# -*- coding:utf-8 -*-

import time
import datetime


def convert_date_to_timestamp(date_str=''):
    timestamp = None
    for date_format in ["%d-%b-%Y %H:%M:%S utc", "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%dt%H:%M:%S.0z", "%Y-%m-%dt%H:%M:%S.00z", "%Y-%m-%dt%H:%M:%S%z", "%Y-%m-%d"]:
        try:
            timestamp = time.mktime(datetime.datetime.strptime(date_str, date_format).timetuple())
        except:
            continue
    return timestamp
