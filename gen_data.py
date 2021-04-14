import multiprocessing
import time
from io import StringIO

import arrow
from dateutil.tz import tz
from nsfocus.dbconnection import Dbconnection as DB
from nsfocus.optionparser import OptionParser

# snap 0-12
# 5mi 12-5*24
# hour > 5*24

# 5 x 2048

SMG = 1
TABLES = set()

BATCH_SIZE = 5000
ATTACK_TYPE = ["SYN Flood", "ACK Flood", "UDP Flood", "ICMP Flood", "HTTP Flood", "IGMP Flood", "DNS Amplification"]


class DBCopy(DB):

    def copy_from(self, data, table, seq='\t', null='\\N', size=-1, columns=None):
        cur = None
        try:
            tmp = []
            for ii in data:
                tmp.append(seq.join([str(jj) for jj in ii]))

            file = StringIO('\n'.join(tmp))
            cur = self._conn.cursor()
            cur.copy_from(file, table, seq, null, size, columns)
            self._conn.commit()
            return True
        except Exception as e:
            print(e)
            self._conn.rollback()
            return False
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass


def gen_dst_ips(start=17, end=129):
    for ii in range(1, start):
        for jj in range(1, end):
            yield '103.31.%s.%s' % (ii, jj)


def create_sub_table(table, start, db, interval='day'):
    start = arrow.get(start).to('local')
    stat_time = start.format('YYYY-MM-DD HH:mm:ss')

    if 'day' == interval:
        key = start.format('YYYY-MM-DD')
    elif 'week' == interval:
        key = start.span('week')[0].format('YYYY-MM-DD')
    elif 'month' == interval:
        key = start.format('YYYY-MM-01')
    else:
        key = start.format('YYYY-MM-DD')

    if key not in TABLES:
        sql = "select create_traffic_subtable(%s, %s, %s)"
        params = (table, interval, stat_time)
        db.execute(sql, params)
        TABLES.add(key)
        print('<%s> Create sub table: %s.' % (table, key))


def gen_ads_dst_ip_traffic_hour(start, end, smg):
    def f(now):
        tmp = []
        for ii in gen_dst_ips(end=201):
            tmp.append([smg, now,
                        96426290, 94157, 204799200, 199980,
                        86668589, 84637, 184074880, 179760,
                        9757701, 9520, 20724320, 20220,
                        ii, '中国', '河南', '信阳'])
        return tmp

    columns = ['customer_line_id', 'stat_time',
               'avg_in_bps', 'avg_in_pps', 'max_in_bps', 'max_in_pps',
               'avg_drop_bps', 'avg_drop_pps', 'max_drop_bps', 'max_drop_pps',
               'avg_pass_bps', 'avg_pass_pps', 'max_pass_bps', 'max_pass_pps',
               'dstip', 'country', 'provence', 'city']

    copy_to_db(columns, start, end, 't_ads_customerline_dstip_traffic_hour', f)


def gen_ads_dst_ip_traffic_5mi(start, end, smg):
    def f(now):
        tmp = []
        for ii in gen_dst_ips(end=201):
            tmp.append([smg, now,
                        184319280, 179982, 307198800, 299970,
                        165667392, 161784, 276112320, 269640,
                        18651888, 18198, 31086480, 30330,
                        ii, '中国', '河南', '信阳'])
        return tmp

    columns = ['customer_line_id', 'stat_time',
               'avg_in_bps', 'avg_in_pps', 'max_in_bps', 'max_in_pps',
               'avg_drop_bps', 'avg_drop_pps', 'max_drop_bps', 'max_drop_pps',
               'avg_pass_bps', 'avg_pass_pps', 'max_pass_bps', 'max_pass_pps',
               'dstip', 'country', 'provence', 'city']

    copy_to_db(columns, start, end, 't_ads_customerline_dstip_traffic_5mi', f)


def gen_ads_traffic_5mi(start, end, smg):
    def f(now):
        tmp = []
        for ii in range(20):
            tmp.append([0 if ii else smg, now,
                        71302889472, 69625037, 251657256960, 245735424,
                        64087510221, 62585242, 226191212544, 220889088,
                        7215379251, 7039795, 25466044416, 24846336])
        return tmp

    columns = ['customer_line_id', 'stat_time',
               'avg_in_bps', 'avg_in_pps', 'max_in_bps', 'max_in_pps',
               'avg_drop_bps', 'avg_drop_pps', 'max_drop_bps', 'max_drop_pps',
               'avg_pass_bps', 'avg_pass_pps', 'max_pass_bps', 'max_pass_pps']

    copy_to_db(columns, start, end, 't_ads_customerline_traffic_5mi', f)


def gen_ads_traffic_hour(start, end, smg):
    def f(now):
        tmp = []
        for ii in range(20):
            tmp.append([0 if ii else smg, now,
                        11080332, 9006, 13975456, 10097,
                        582981, 390, 1104360, 484,
                        10497352, 8616, 12871096, 9656])
        return tmp

    columns = ['customer_line_id', 'stat_time',
               'avg_in_bps', 'avg_in_pps', 'max_in_bps', 'max_in_pps',
               'avg_drop_bps', 'avg_drop_pps', 'max_drop_bps', 'max_drop_pps',
               'avg_pass_bps', 'avg_pass_pps', 'max_pass_bps', 'max_pass_pps']

    copy_to_db(columns, start, end, 't_ads_customerline_traffic_hour', f)


def gen_ads_event(start, end, smg):
    def f(now):
        tmp = []
        num = 0
        for ii in gen_dst_ips(start=13, end=129):
            jj = ATTACK_TYPE[num % 7]
            num += 1
            tmp.append(['202.10.16.11', smg, 1,
                        ii, jj, now, arrow.get(now, format, tzinfo=tz.tzlocal()).shift(minutes=1).format('YYYY-MM-DD HH:mm:ss'),
                        276112380, 269640, 276112380, 26964,
                        9203746, 8988, 9203746, 8988,
                        '中国', '河南', '信阳', '223'])
        return tmp

    columns = ['device_ip', 'customer_line_id', 'customer_scope_id',
               'dstip', 'attack_type', 'start_time', 'end_time',
               'total_in_bits', 'total_in_packets', 'total_drop_bits', 'total_drop_packets',
               'max_in_bps', 'max_in_pps', 'max_drop_bps', 'max_drop_pps',
               'country', 'provence', 'city', 'attack_port']

    copy_to_db(columns, start, end, 't_ads_event', f)


def copy_to_db(columns, start, end, table, f):
    """
    Args:
        f: function to generate rows to be copied to table.
    """
    print('------------------------->')
    print('<%s> Prepare to generate data: %s - %s.' % (
        table, arrow.get(start).to('local').format('YYYY-MM-DD HH:mm:ss'), arrow.get(end).to('local').format('YYYY-MM-DD HH:mm:ss')))

    init = time.time()

    # duration: 创建子表使用, 指单个子表保存数据的时间
    # interval: 生成数据的间隔, 指数据之间stat_time间隔时间
    if table.endswith('5mi'):
        duration = 'day'
        interval = 300
    elif table.endswith('hour'):
        duration = 'week'
        interval = 3600
    elif table == 't_ads_event':
        duration = 'month'
        interval = 3600
    else:
        duration = 'week'
        interval = 3600

    start = start - start % interval + interval if start % interval else start

    db = DBCopy()

    res = list()
    while start <= end:
        create_sub_table(table, start, db, interval=duration)
        stat_time = arrow.get(start).to('local').format('YYYY-MM-DD HH:mm:ss')

        tmp = f(stat_time)
        if tmp:
            res.extend(tmp)
            if BATCH_SIZE <= len(res):
                db.copy_from(res, table, columns=columns)
                print('<{}> Copy to sub table, last record stat_time: <{}>, num: {}'.format(table, stat_time, len(res)))
                res.clear()

        start += interval

    if res:
        stat_time = arrow.get(start - interval).to('local').format('YYYY-MM-DD HH:mm:ss')
        db.copy_from(res, table, columns=columns)
        print('<{}> Copy to sub table, last record stat_time: {}, num: {}'.format(table, stat_time, len(res)))

    print('<%s> Data generation successfully, total time: %ss.' % (table, str(int(time.time() - init))))
    print('<-------------------------')


if __name__ == '__main__':
    parser = OptionParser()
    """ Required options. """
    parser.add_option("-s", '--start', dest='start_time', metavar='2021-01-01 00:00:00', required=True, help="Start Time")
    parser.add_option("-e", '--end', dest='end_time', metavar='2021-01-01 00:00:00', required=False, help="End Time")
    parser.add_option("-m", '--smg', dest='smg', required=False, help="Scrubbing monitor group id")

    (options, args) = parser.parse_args()
    format = 'YYYY-MM-DD HH:mm:ss'
    options.start_time = arrow.get(options.start_time, format, tzinfo=tz.tzlocal()).timestamp
    options.end_time = arrow.get(options.end_time, format, tzinfo=tz.tzlocal()).timestamp if options.end_time else time.time()

    if not options.sn:
        options.sn = SMG

    if options.start_time >= options.end_time:
        print('Start time cannot great then end time.')
        exit(1)

    p = []
    dst_tables = [gen_ads_dst_ip_traffic_5mi, gen_ads_dst_ip_traffic_hour, gen_ads_traffic_hour, gen_ads_traffic_5mi]
    for i in dst_tables:
        j = multiprocessing.Process(target=i, args=(options.start_time, options.end_time, options.sn))
        j.start()
        p.append(j)

    for i in p:
        i.join()
