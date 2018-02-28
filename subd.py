#!/usr/bin/env python
#-*- coding:utf-8 -*-

import multiprocessing
import os
import argparse
import time
import dns.resolver
from altdns import altdns
from sublist3r import sublist3r

def resolver(domains):
    result = {}
    for domain in domains:
        try:
            answers = dns.resolver.query(domain, 'A')
            ips = ', '.join([answer.address for answer in answers])
        except:
            ips = ''
        result[domain] = ips
    return result

def main():
    parser = argparse.ArgumentParser(description=u'结合了sublist3r,'+\
            u'subDomainsBrute, altdns 功能的子域名查找器',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
            Example:
                    ./subd.py example.com
                    ./subd.py example.com -t 1
                    ./subd.py example.com -o example.txt''')

    parser.add_argument('domain', help=u'目标域名')
    parser.add_argument('-t', '--type', help=u'查找类型，默认是0,即使用'+\
            u'三个模块，1 只使用sublist3r, 2 只使用sublist3r,' + \
            u'subDomainsBrute.', default=0, type=int)
    parser.add_argument('--threads', default='10,3,20,20', help=u'默认'+\
            u'值为10,3,20,20. 10为sublist3r的线程数，3为subDomainsBrute'+\
            u'进程数，20为subDomainsBrute线程数。20为altdns线程数.')
    parser.add_argument('-o', '--output', default='domains.txt',
            help=u'输出写入的文件')
    parser.add_argument('-e', '--engines', help=u'sublist3r使用的搜索引擎，'+\
            u'可以使用的有：baidu, yahoo, google, bing, ask, netcraft,' + \
            'dnsdumpster, virustotal, threatcrowd, ssl, passivedns',
            default=None)
     
    args = parser.parse_args()
    
    sl_threads, sd_process, sd_threads, ad_threads = args.threads.split(',')
    
    sl_result = sublist3r.main(args.domain.strip(), int(sl_threads), args.engines)

    result = resolver(sl_result)
    
    if args.type == 0 or args.type == 2:
        from subDomainsBrute import subDomainsBrute
        subDomainsBrute.main(args.domain.strip(), int(sd_threads),
                int(sd_process), result)

    tmp_dir = os.environ['HOME'] + '/Desktop/' + args.domain.strip() + str(int(time.time()))
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    
    domains_file = tmp_dir + '/' + args.output
    domains_ip_file = tmp_dir + '/ip_' + args.output

    with open(domains_file, 'w') as tmp_f:
        for d in result.keys():
            tmp_f.write(d + '\n')
    with open(domains_ip_file, 'w') as tmp_f:
        for i in result.items():
            tmp_f.write(i[0] + '\t' + i[1] + '\n')

    if args.type == 0:
        tmp_outputfile = tmp_dir + '/altdnsoutput.txt'
        tmp_save = tmp_dir + '/save.txt'
        altdns.main(domains_file, tmp_outputfile, int(ad_threads), tmp_save)
    print('Result in %s, %s' % (domains_file, domains_ip_file)) 

if __name__ == '__main__':
    main()
