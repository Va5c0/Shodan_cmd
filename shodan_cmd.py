#!/usr/bin/env python
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
import shodan
import os
import time


def clean():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system('tput reset')


class colors:
    FAIL = '\033[91m'
    GREEN = '\033[32m'
    INFO = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class Shodan_class(object):

    def __init__(self, API_KEY):
        self.api = shodan.Shodan(API_KEY)

    def search(self, query, pag):
        try:
            result = self.api.search(str(query), pag)
        except Exception as e:
            print(colors.FAIL + "\n [!] ERROR: " + colors.ENDC + str(e))
            result = []
        return result

    def info(self, res, sfile):
        if sfile is None:
            i = 0
            for r in res['matches']:
                print("\n [+]" + colors.INFO + " IP: " + colors.ENDC + r.get('ip_str'))
                print("  [-]" + colors.INFO + " Product: " + colors.ENDC + str(r.get('product')))
                print("  [-]" + colors.INFO + " Transport: " + colors.ENDC + str(r.get('transport')))
                print("  [-]" + colors.INFO + " Port: " + colors.ENDC + str(r.get('port')))
                print("  [-]" + colors.INFO + " OS: " + colors.ENDC + str(r.get('os')))
                print("  [-]" + colors.INFO + " Country: " + colors.ENDC + str(r['location']['country_name']))
                print("  [-]" + colors.INFO + " City: " + colors.ENDC + str(r['location']['city']))
                print("  [-]" + colors.INFO + " Latitude: " + colors.ENDC + str(r['location']['latitude']))
                print("  [-]" + colors.INFO + " Longitude: " + colors.ENDC + str(r['location']['longitude']))
                print("  [-]" + colors.INFO + " Hostnames: " + colors.ENDC + str(r.get('hostnames')))
                print("  [-]" + colors.INFO + " Timestamp: " + colors.ENDC + str(r.get('timestamp')))
                print("  [-]" + colors.INFO + " Data: \n" + colors.ENDC + str(r['data']))
                i += 1
                if i == 2:
                    raw_input("\npress enter to continue...")
                    i = 0
        else:
            with open(sfile, "a+") as f:
                for r in res['matches']:
                    f.write("\n\n [+] IP: " + r.get('ip_str'))
                    f.write("\n  [-] Product: " + str(r.get('product')))
                    f.write("\n  [-] Transport: " + str(r.get('transport')))
                    f.write("\n  [-] Port: " + str(r.get('port')))
                    f.write("\n  [-] OS: " + str(r.get('os')))
                    f.write("\n  [-] Country: " + str(r['location']['country_name']))
                    f.write("\n  [-] City: " + str(r['location']['city']))
                    f.write("\n  [-] Latitude: " + str(r['location']['latitude']))
                    f.write("\n  [-] Longitude: " + str(r['location']['longitude']))
                    f.write("\n  [-] Hostnames: " + str(r.get('hostnames')))
                    f.write("\n  [-] Timestamp: " + str(r.get('timestamp')))
                    f.write("\n  [-] Data: \n" + str(r['data']))
            print(" [i] " + colors.GREEN + "File saved!!\n" + colors.ENDC)

    def host(self, ip, sfile):
        try:
            host = self.api.host(ip)
            if sfile is None:
                print("\n [+]" + colors.INFO + "IP: " + colors.ENDC + host.get('ip_str'))
                print("  [-]" + colors.INFO + "Country: " + colors.ENDC + host.get('country_name', 'Unknown'))
                print("  [-]" + colors.INFO + "City: " + colors.ENDC + str(host.get('city', 'Unknown')))
                print("  [-]" + colors.INFO + "Latitude: " + colors.ENDC + str(host.get('latitude')))
                print("  [-]" + colors.INFO + "Longitude: " + colors.ENDC + str(host.get('longitude')))
                print("  [-]" + colors.INFO + "Hostnames: " + colors.ENDC + str(host.get('hostnames')))
                for x in host['data']:
                    print("\n  [-]" + colors.INFO + "Port: " + colors.ENDC + str(x['port']))
                    print("  [-]" + colors.INFO + "Protocol: " + colors.ENDC + x['transport'])
                    print(x['data'])
            else:
                with open(sfile, 'a+') as f:
                    f.write("\n\n [+] IP: " + host.get('ip_str'))
                    f.write("\n  [-] Country: " + host.get('country_name', 'Unknown'))
                    f.write("\n  [-] City: " + str(host.get('city', 'Unknown')))
                    f.write("\n  [-] Latitude: " + str(host.get('latitude')))
                    f.write("\n  [-] Longitude: " + str(host.get('longitude')))
                    f.write("\n  [-] Hostnames: " + str(host.get('hostnames')))
                    for x in host['data']:
                        f.write("\n  [-] Port: " + str(x['port']))
                        f.write("\n  [-] Protocol: " + x['transport'] + "\n")
                        f.write(x['data'])
                print(" [i] " + colors.GREEN + "File saved!!\n" + colors.ENDC)
        except Exception as e:
            print(colors.FAIL + colors.BOLD + "\n [!] ERROR: " + colors.ENDC + str(e) + "\n")

    def services(self, sfile):
        result = self.api.services()
        if sfile is None:
            for x, y in result.items():
                print(" [-] " + colors.GREEN + x + ": " + colors.ENDC + y)
        else:
            with open(sfile, 'w') as f:
                for x, y in result.items():
                    f.write("\n [-] %s: %s" % (x, y))
            print(" [i] " + colors.GREEN + "File saved!!\n" + colors.ENDC)

    def protocols(self, sfile):
        result = self.api.protocols()
        if sfile is None:
            for x, y in result.items():
                print(" [-] " + colors.GREEN + x + ": " + colors.ENDC + y)
        else:
            with open(sfile, 'w') as f:
                for x, y in result.items():
                    f.write("\n [-] %s: %s" % (x, y))
            print(" [i] " + colors.GREEN + "File saved!!\n" + colors.ENDC)

    def queries(self, pag, sort, order, sfile):
        res = self.api.queries(page=pag, sort=sort, order=order)
        if sfile is None:
            i = 0
            for r in res['matches']:
                print("\n [+]" + colors.INFO + " Title: " + colors.ENDC + r.get('title', 'Unknown'))
                print("  [-]" + colors.INFO + " Description: " + colors.ENDC + r.get('description', 'Unknown'))
                print("  [-]" + colors.INFO + " Query: " + colors.ENDC + r.get('query', 'Unknown'))
                print("  [-]" + colors.INFO + " Votes: " + colors.ENDC + str(r.get('votes')))
                print("  [-]" + colors.INFO + " Timestamp: " + colors.ENDC + r.get('timestamp'))
                print("  [-]" + colors.INFO + " Tags: " + colors.ENDC + str(r.get('tags', 'Unknown')))
                i += 1
                if i == 3:
                    raw_input("\npress enter to continue...")
                    i = 0
        else:
            with open(sfile, "a+") as f:
                for r in res['matches']:
                    f.write("\n\n [+] Title: " + r.get('title', 'Unknown'))
                    f.write("\n  [-] Description: " + r.get('description', 'Unknown'))
                    f.write("\n  [-] Query: " + r.get('query', 'Unknown'))
                    f.write("\n  [-] Votes: " + str(r.get('votes')))
                    f.write("\n  [-] Timestamp: " + r.get('timestamp'))
                    f.write("\n  [-] Tags: " + str(r.get('tags', 'Unknown')))
            print(" [i] " + colors.GREEN + "File saved!!\n" + colors.ENDC)

    def queries_search(self, query, pag, sfile):
        res = self.api.queries_search(query, pag)
        if sfile is None:
            i = 0
            for r in res['matches']:
                print("\n [+]" + colors.INFO + " Title: " + colors.ENDC + r.get('title', 'Unknown'))
                print("  [-]" + colors.INFO + " Description: " + colors.ENDC + r.get('description', 'Unknown'))
                print("  [-]" + colors.INFO + " Query: " + colors.ENDC + r.get('query', 'Unknown'))
                print("  [-]" + colors.INFO + " Votes: " + colors.ENDC + str(r.get('votes')))
                print("  [-]" + colors.INFO + " Timestamp: " + colors.ENDC + r.get('timestamp'))
                print("  [-]" + colors.INFO + " Tags: " + colors.ENDC + str(r.get('tags', 'Unknown')))
                i += 1
                if i == 3:
                    raw_input("\npress enter to continue...")
                    i = 0
        else:
            with open(sfile, "a+") as f:
                for r in res['matches']:
                    f.write("\n\n [+] Title: " + r.get('title', 'Unknown'))
                    f.write("\n  [-] Description: " + r.get('description', 'Unknown'))
                    f.write("\n  [-] Query: " + r.get('query', 'Unknown'))
                    f.write("\n  [-] Votes: " + str(r.get('votes')))
                    f.write("\n  [-] Timestamp: " + r.get('timestamp'))
                    f.write("\n  [-] Tags: " + str(r.get('tags', 'Unknown')))
            print(" [i] " + colors.GREEN + "File saved!!\n" + colors.ENDC)

    def api_info(self):
        result = self.api.info()
        print("\n [i] " + colors.INFO + "API Information:" + colors.ENDC)
        for x, y in result.items():
                print("  [-] " + colors.GREEN + str(x).capitalize() + ": " + colors.ENDC + str(y))

    def alert(self, name, host):
        try:
            alert = self.api.create_alert(name, host)
            for b in self.api.stream.alert(alert['id']):
                print(b)
        except Exception as e:
            print(colors.FAIL + "\n [!] ERROR: " + colors.ENDC + str(e))
            self.api.delete_alert(alert['id'])

    def explts_search(self, query, pag):
        try:
            result = self.api.exploits.search(query, pag)
        except Exception as e:
            print(colors.FAIL + "\n [!] ERROR: " + colors.ENDC + str(e))
            result = []
        return result

    def explts_count(self, query):
        try:
            count = self.api.exploits.count(query)
        except Exception as e:
            print(colors.FAIL + "\n [!] ERROR: " + colors.ENDC + str(e))
            count = []
        return count

    def explts_info(self, res, sfile):
        if sfile is None:
            i = 0
            for r in res['matches']:
                print("\n [+]" + colors.INFO + " ID: " + colors.ENDC + str(r.get('_id')))
                print("  [-]" + colors.INFO + " Author: " + colors.ENDC + r.get('author'))
                print("  [-]" + colors.INFO + " Description: " + colors.ENDC + r.get('description'))
                print("  [-]" + colors.INFO + " Source: " + colors.ENDC + r.get('source'))
                print("  [-]" + colors.INFO + " Platform: " + colors.ENDC + r.get('platform'))
                print("  [-]" + colors.INFO + " Type: " + colors.ENDC + r.get('type'))
                print("  [-]" + colors.INFO + " Port: " + colors.ENDC + str(r.get('port')))
                print("  [-]" + colors.INFO + " CVE: " + colors.ENDC + str(r.get('cve')))
                print("  [-]" + colors.INFO + " Date: " + colors.ENDC + r.get('date'))
                i += 1
                if i == 3:
                    raw_input("\npress enter to continue...")
                    i = 0
        else:
            with open(sfile, "w") as f:
                for r in res['matches']:
                    f.write("\n\n [+] ID: " + str(r.get('_id')))
                    f.write("\n  [-] Author: " + r.get('author'))
                    f.write("\n  [-] Description: " + r.get('description'))
                    f.write("\n  [-] Source: " + r.get('source'))
                    f.write("\n  [-] Platform: " + r.get('platform'))
                    f.write("\n  [-] Type: " + r.get('type'))
                    f.write("\n  [-] Port: " + str(r.get('port')))
                    f.write("\n  [-] CVE: " + str(r.get('cve')))
                    f.write("\n  [-] Date: " + r.get('date'))
            print(" [i] " + colors.GREEN + "File saved!!\n" + colors.ENDC)

    def report(self, res, field, sfile):
        loc = ['longitude', 'latitude', 'country_name', 'city']
        if sfile is None:
            for r in res['matches']:
                if "," in field:
                    lfield = field.split(",")
                    for f in lfield:
                        if f in loc:
                            print(str(r['location'][f])),
                        else:
                            print(str(r.get(f))),
                    print("\n")
                else:
                    if field in loc:
                        print(str(r['location'][field]))
                    else:
                        print(str(r.get(field)))
        else:
            with open(sfile, 'w') as f:
                for r in res['matches']:
                    if "," in field:
                        lfield = field.split(",")
                        for fl in lfield:
                            if fl in loc:
                                f.write(str(r['location'][fl]))
                                f.write(",")
                            else:
                                f.write(str(r.get(fl)))
                                f.write(",")
                        f.write("\n")
                    else:
                        if field in loc:
                            f.write("\n " + str(r['location'][field]))
                        else:
                            f.write("\n " + str(r.get(field)))
            print("\n [i] " + colors.GREEN + "File saved!!\n" + colors.ENDC)


VERSION = "1.0"

SAMPLES = """
Type ./shodan.py -h to show help

Command line examples:

    1- Get information about:
        - API : ./shodan_cmd.py -I api
        - Protocols : ./shodan_cmd.py -I protocols
        - Services : ./shodan_cmd.py -I services
        - Queries : ./shodan_cmd.py -I queries -p [pag num] --sort [votes/timestamp] --order [desc/asc]

    2- Search in queries posted by users
    ./shodan_cmd.py -Q [query] -p [pag num]

    3- Search in Shodan
    ./shodan_cmd.py -S [query] -p [pag num]

    4- Get info about host
    ./shodan_cmd.py -H [host]

    5- Search a range of hosts
    ./shodan_cmd.py -R [ip/range]

    6- Search exploits
    ./shodan_cmd.py -E [query]
        - Possible search filters:
            author    bid    code    cve    date    platform
            type    osvdb    msb    port    title    description
        - Example: ./shodan_cmd.py -E 'ftp type:remote platform:linux'

    7- Show a report with selected field/s
    ./shodan_cmd.py -S [query] -r [field/s]
        -Possible fields
            product    ip_str    port    hostnames    city
            longitude    latitude    country_name    os
            timestamp    transport    data    isp    asn
        - Example: ./shodan_cmd.py -S 'ftp anonymous' -r country_name,city

    ### All options support the argument [-o] to save result in a file. ###
    """


def main():
    argp = ArgumentParser(
            description="Shodan",
            usage="./shodan.py [options] \nSamples: ./shodan.py",
            version="Shodan Tool v" + VERSION)

    argp.add_argument('-I', '--info', dest='info', type=str,
                      help='Get info about: services, protocols, queries and api')

    argp.add_argument('-Q', '--queries', dest='queries', type=str,
                      help='Search in queries posted by users')

    argp.add_argument('-S', '--search', dest='search', type=str,
                      help='Search in Shodan')

    argp.add_argument('-H', '--host', dest='host', type=str,
                      help='Search host in Shodan')

    argp.add_argument('-R', '--range', dest='range', type=str,
                      help='Range of hosts to search in Shodan')

    argp.add_argument('-E', '--exploits', dest='exploits', type=str,
                      help='Search exploits in Shodan')

    argp.add_argument('-A', '--alert', dest='alert', type=str,
                      help='Active alert of one host or range')

    argp.add_argument('-p', '--page', dest='page', type=int,
                      help='Page number to iterate over results (10 items per page)')

    argp.add_argument('--sort', dest='sort', type=str,
                      help='Sort the result based on a property (Values: votes, timestamp')

    argp.add_argument('--order', dest='order', type=str,
                      help='Whether to sort the list in ascending or descending order (Values: asc, desc)')

    argp.add_argument('-o', '--output', dest='output', type=str,
                      help='Output file to save results')

    argp.add_argument('-r', '--report', dest='report', type=str,
                      help='Show a report with selected field/s')

    args = argp.parse_args()

    API_KEY = "8rJMGUqgsAXWFwWxoCqhnQ74Mw88KM86"
    shd = Shodan_class(API_KEY)

    if args.info:  # INFO
        if args.info.lower() == "services":
            shd.services(args.output)
        elif args.info.lower() == "protocols":
            shd.protocols(args.output)
        elif args.info.lower() == "queries":
            if args.sort and args.order:
                for pag in range(1, args.page + 1):
                    shd.queries(pag, args.sort, args.order, args.output)
            else:
                print(SAMPLES)
        elif args.info.lower() == "api":
            shd.api_info()
        else:
            print(SAMPLES)

    elif args.queries:  # SEARCH QUERIES
        for pag in range(1, args.page + 1):
            shd.queries_search(args.queries, pag, args.output)

    elif args.search and not args.report:  # SEARCH
        if not args.page:
            args.page = 1
        for pag in range(1, args.page + 1):
            result = shd.search(args.search, pag)
            if len(result) != 0:
                print("\n [i] " + colors.GREEN + "Total results: " + colors.ENDC + str(result['total']))
                shd.info(result, args.output)

    elif args.host:  # HOST
        shd.host(args.host, args.output)

    elif args.range:  # RANGE
        rng = args.range
        ip = rng.split('/')[0]
        base = ip.split('.')[:3]
        range1 = int(ip.split('.')[3])
        range2 = int(rng.split('/')[1])
        for i in range(range1, range2):
            host = '.'.join(base) + '.' + str(i)
            shd.host(host, args.output)
            time.sleep(1)

    elif args.alert:  # ALERT
        info = args.alert.strip(",")
        shd.alert(info[0], info[1])

    elif args.exploits:  # EXPLOITS
        count = shd.explts_count(args.exploits)
        print("\n [i]" + colors.INFO + " Total results: " + colors.GREEN + str(count['total']) + colors.ENDC)
        time.sleep(1)
        res = shd.explts_search(args.exploits, args.page)
        if len(res) != 0:
            shd.explts_info(res, args.output)

    elif args.report:  # REPORT
        res = shd.search(args.search, args.page)
        print("\n [i] " + colors.GREEN + "Total results: " + colors.ENDC + str(res['total']))
        shd.report(res, args.report, args.output)

    else:
        print(SAMPLES)


if __name__ == "__main__":
    main()