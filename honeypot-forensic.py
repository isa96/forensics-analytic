from igraph import *
from tqdm import tqdm
import apache_log_parser
import pygeoip
import scalp
import pandas as pd


def ip_to_city(ip_address):
    gi = pygeoip.GeoIP('GeoLiteCity.dat')
    record = gi.record_by_addr(str(ip_address))
    city, country = 'n/a', 'n/a'

    if record:
        if record['city'] and not record['country_code']:
            city, country = record['city'], 'n/a'
        elif record['city'] and record['country_code']:
            city, country = record['city'], record['country_code']

    return city.encode('utf-8'), country.encode('utf-8')


def cluster_attack(g, ip_list, attack_list, attackroot_id):
    # add edge from every vertex which has same ip address and same attack type to cluster root
    # cluster root is the first vertex found
    print 'Proccessing cluster by attack ...'
    for ip in tqdm(ip_list):
        for al in attack_list:
            cluster_att = g.vs.select(ipaddr_eq=ip, attack_type_eq=al)

            if len(cluster_att) > 0:
                g.add_vertex(id=attackroot_id, name=str(attackroot_id),
                             city=cluster_att[0]["city"], country=cluster_att[0]["country"],
                             attack_type=al, ipaddr=ip, is_attackroot=True,
                             is_iproot=False, is_cityroot=False, is_countryroot=False, is_mainroot=False,
                             level="Level 5", node_size=2)

                for ca in cluster_att:
                    g.add_edge(source=ca["id"], target=attackroot_id)

                attackroot_id += 1

    return attackroot_id
                    

def cluster_ipaddr(g, ip_list, iproot_id):
    # add edge from every vertex in cluster to cluster root
    # ip-cluster root is the first vertex found
    print 'Proccessing cluster by IP address ...'
    for ip in tqdm(ip_list):
        cluster_ip = g.vs.select(ipaddr_eq=ip, is_attackroot_eq=True)

        if len(cluster_ip) > 0:
            g.add_vertex(id=iproot_id, name=str(iproot_id), ipaddr=ip, is_attackroot=False,
                         city=cluster_ip[0]["city"], country=cluster_ip[0]["country"],
                         is_iproot=True, is_cityroot=False, is_countryroot=False, is_mainroot=False,
                         level="Level 4", node_size=3)

            for ci in cluster_ip:
                g.add_edge(source=ci["id"], target=iproot_id)

            iproot_id += 1

    return iproot_id


def cluster_city(g, city_list, cityroot_id):
    print 'Proccessing cluster by city ...'
    for cl in tqdm(city_list):
        cluster_ct = g.vs.select(city_eq=cl, is_iproot_eq=True)

        if cluster_ct:
            g.add_vertex(id=cityroot_id, name=str(cityroot_id), is_attackroot=False,
                         city=cluster_ct[0]["city"], country=cluster_ct[0]["country"],
                         is_iproot=False, is_cityroot=True, is_countryroot=False, is_mainroot=False,
                         level="Level 3", node_size=4)

            for cc in cluster_ct:
                g.add_edge(source=cc["id"], target=cityroot_id)

            cityroot_id += 1

    return cityroot_id


def cluster_country(g, country_list, countryroot_id):
    # creating edge from ip-cluster root to country-cluster root
    # country-cluster root is the first vertex found
    print 'Proccessing cluster by country ...'
    for cl in tqdm(country_list):
        cluster_cntry = g.vs.select(country_eq=cl, is_cityroot_eq=True)

        if cluster_cntry:
            g.add_vertex(id=countryroot_id, name=str(countryroot_id), is_attackroot=False,
                         country=cluster_cntry[0]["country"],
                         is_iproot=False, is_cityroot=False, is_countryroot=True, is_mainroot=False,
                         level="Level 2", node_size=5)

            for cc in cluster_cntry:
                g.add_edge(source=cc["id"], target=countryroot_id)

            countryroot_id += 1

    return countryroot_id


def cluster_all(g, mainroot_id):
    # add vertex as the main root
    g.add_vertex(id=mainroot_id, name=str(mainroot_id), is_attackroot=False,
                 is_iproot=False, is_cityroot=False, is_countryroot=False, is_mainroot=True,
                 level="Level 1", node_size=6)
    
    # get country root
    country_root = g.vs.select(is_countryroot=True)
    print 'Proccessing cluster all ...'
    for cr in tqdm(country_root):
        g.add_edge(source=cr["id"], target=mainroot_id)


def build_graph(access_log, illust_country):
    with open(access_log, 'r') as f:
        logs = f.readlines()

    index = 0
    parser = apache_log_parser.Parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")
    g = Graph()
    report = []

    print 'Generating vertices ...'
    for log in tqdm(logs):
        # parse each log and add vertex
        data = parser.parse(log)
        
        # get attack type
        city, country = ip_to_city(data['remote_host'])
        attack_type, attack_description = scalp.main(2, '', [log])
        if illust_country and country in illust_country:
            g.add_vertex(id=index, name=str(index), ipaddr=data['remote_host'],
                         timestamp=data['time_received_tz_datetimeobj'],
                         raw=data['request_first_line'], referer=data['request_header_referer'],
                         user_agent=data['request_header_user_agent'], city=city, country=country,
                         attack_type=attack_type, attack_description=attack_description, is_attackroot=False,
                         is_iproot=False, is_cityroot=False, is_countryroot=False, is_mainroot=False,
                         level="Level 6", node_size=1)
            index += 1

        elif not illust_country:
            g.add_vertex(id=index, name=str(index), ipaddr=data['remote_host'],
                         timestamp=data['time_received_tz_datetimeobj'],
                         raw=data['request_first_line'], referer=data['request_header_referer'],
                         user_agent=data['request_header_user_agent'], city=city, country=country,
                         attack_type=attack_type, attack_description=attack_description, is_attackroot=False,
                         is_iproot=False, is_cityroot=False, is_countryroot=False, is_mainroot=False,
                         level="Level 6", node_size=1)

            index += 1

        if attack_type is not 'Normal':
            report.append([data['remote_host'], city, country, attack_type])

    # get list of attack, ip address, and city
    attack_list = set(g.vs["attack_type"])
    ip_list = set(g.vs["ipaddr"])
    city_list = set(g.vs["city"])
    country_list = set(g.vs["country"])

    # cluster based on attack, ip address, country, and joining all cluster
    iproot_id = cluster_attack(g, ip_list, attack_list, index)
    cityroot_id = cluster_ipaddr(g, ip_list, iproot_id)
    countryroot_id = cluster_city(g, city_list, cityroot_id)
    mainroot_id = cluster_country(g, country_list, countryroot_id)
    cluster_all(g, mainroot_id)

    g.write_graphml('g.graphml')

    # report
    df = pd.DataFrame(report, columns=['ip', 'city', 'country', 'attack'])
    df_attack = df.groupby(['attack', 'country', 'city']).city.count()
    report_attack = pd.DataFrame(df_attack)
    report_attack.to_csv('report_attack.csv', encoding='utf-8')

    df_ip = df.groupby(['ip', 'attack']).attack.count()
    report_ip = pd.DataFrame(df_ip)
    report_ip.to_csv('report_ip.csv', encoding='utf-8')


# illustration_country = []
illustration_country = ['HU', 'KR']
build_graph('/home/Downloads/var/log/httpd/access_log', illustration_country)
