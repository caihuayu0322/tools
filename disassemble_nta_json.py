import os
import re


def find_field_val(content, field):
    if field in content:
        res = re.match(r'^.*"%s":\s*(\d+).*' % field, content)
        if res:
            return int(res[1])
    return 0


def acc_field_val_sum(path, field):
    """
    traffic json 分为两个部分，
    1. region total traffic 统计内容
    2. region top 300 ip detail 统计内容
    region 超过300 ip时，total traffic 理应大于 top 300ip 统计内容
    不超过300 ip时, total traffic 理应等于 top 300ip 统计内容
    """
    if not os.path.exists(path):
        print(f'File <{path}> not exists.')

    with open(path, 'r') as fp:
        content = fp.readline()
        field_val = 0
        total_val = 0
        total_flag = False
        while content:
            content = content.strip()
            if content:
                if 'totaltraffic' in content:
                    total_flag = True

                if field in content:
                    tmp = find_field_val(content, field)
                    if total_flag:
                        total_val += tmp
                        total_flag = False
                    else:
                        field_val += tmp

            content = fp.readline()

        print('Total value: {}; IP detail value: {}; 误差率: {}'.format(total_val, field_val, '%.4f' % (1 - field_val / total_val)))
        return total_val, field_val


if __name__ == '__main__':
    acc_field_val_sum('./NTA-10.66.243.202-1611992940-traffic.json', 'rx_bps')
