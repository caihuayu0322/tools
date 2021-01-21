from lxml import etree


def extract_event(element):
    max_in_bps = int(int(element.get('attackFlowBt')) * 8)
    max_in_pps = int(int(element.get('attackFlowPkg')))
    max_drop_bps = int(int(element.get('filterFlowBt')) * 8)
    max_drop_pps = int(int(element.get('filterFlowPkg')))
    max_pass_bps = max_in_bps - max_drop_bps
    max_pass_pps = max_in_pps - max_drop_pps

    return {
        'dstip': element.get('dstIP'),
        'max_in_bps': max_in_bps,
        'max_in_pps': max_in_pps,
        'max_drop_bps': max_drop_bps,
        'max_drop_pps': max_drop_pps,
        'max_pass_bps': max_pass_bps,
        'max_pass_pps': max_pass_pps,
        'attack_type': element.get('attackType')
    }


def extract_flow(element):
    if '0' == element.get('direction'):
        max_in_bps = int(int(element.get('totalInBps')) * 8 * 30)
        max_in_pps = int(element.get('totalInPps') * 30)
        max_pass_bps = int(int(element.get('totalOutBps')) * 8 * 30)
        max_pass_pps = int(element.get('totalOutPps') * 30)
        max_drop_bps = max_in_bps - max_pass_bps
        max_drop_pps = max_in_pps - max_pass_pps

        return {
            'dstip': element.get('dstIP'),
            'max_in_bps': max_in_bps,
            'max_in_pps': max_in_pps,
            'max_drop_bps': max_drop_bps,
            'max_drop_pps': max_drop_pps,
            'max_pass_bps': max_pass_bps,
            'max_pass_pps': max_pass_pps
        }


def extract_element(root, element):
    elements = root.findall(element)
    res = []

    if element == 'AttackEvent':
        res = list(filter(None, [extract_event(i) for i in elements]))
    elif element == 'CollapsarFlow':
        res = list(filter(None, [extract_flow(i) for i in elements]))

    return res


def compares(events, flows, field):
    print('--------------------->')
    event = sum([i[field] for i in events])
    print(f"event: {field}/{event}")
    flow = sum([i[field] for i in flows])
    print(f"flow: {field}/{flow}")


def group_by_attack_type(events, filed):
    tmp = {}
    for i in events:
        if i['attack_type'] not in tmp:
            tmp[i['attack_type']] = 0

        tmp[i['attack_type']] += i[filed]

    print(tmp)


def main(path):
    root = etree.parse(path)
    events = extract_element(root, 'AttackEvent')
    flows = extract_element(root, 'CollapsarFlow')

    compares(events, flows, 'max_in_bps')
    compares(events, flows, 'max_drop_bps')

    group_by_attack_type(events, 'max_drop_bps')


if __name__ == '__main__':
    main("ADS-[10.107.1.107]-[D684-81B6-8F24-C664]-traffic-20210119030052.xml")
