#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import os
import shutil
import re
import random
import subprocess
from config import *

# Первый октет
ptr_prefix_gw = ['mailer', 'gw', 'gate', 'mailgw', 'pool', 'mlgw']
# Второй октет
ptr_prefix_srv = ['box', 'sender', 'srv', 'snd', 'mail', 'server']
# Третий октет
ptr_country = ['eu', 'eu1', 'eu2', 'fl', 'nw', 'euro', 'can', 'rs', 'prod', 'us', 'us1', 'us2', 'usa-north',
               'usa-south', 'usa-west', 'usa-east']

# Индекс элемента в таблице данных начиная с 0
data_map = dict(domain=0, vpsip=1, sublink=2, fbl=3, spf=4, rdns=5, pmta_conf=6, pmta_pref=7)
#global_path = "test/"
global_path = "" #current dir

dirs = dict(records="records/", configs="configs/", dkim="keys/")

debug = False


def create_dirs(dir_dict):
    for dname, d in dir_dict.iteritems():
        if dname == 'records' and not debug:
            continue
        if not os.path.exists(global_path+d):
            os.makedirs(global_path+d)


def clear_files(dir_dict):
    for dname, d in dir_dict.iteritems():
        if dname == 'dkim':
            continue
        for root, ds, fs in os.walk(global_path+d, topdown=False):
            for name in fs:
                os.remove(os.path.join(root, name))
            for name in ds:
                os.rmdir(os.path.join(root, name))


def read_input_data():
    # Формирование таблицы данных
    ## Delimeter 1 space or 1 tab
    # domain	link_sub	vps_ip	spf_record	RDNS/NET
    # tritonchat.com	rafkal	45.58.40.14	77.247.40.0/25	77.247.40.1-127
    # return: [['tritonchat.com', 'rafkal', '45.58.40.14', '77.247.40.0/25', '77.247.40.1-127'],...]
    data = []
    col_count = len(data_map)
    if not os.path.exists("input_table.txt"):
        print "Вставьте данные в файл input_table.txt"
        exit(1)
    for line in open("input_table.txt").readlines():
        # Разделить пробел или таб
        row = re.split(" |\t", line.strip())
        # Добавляем пустые елементы
        row += [""] * (col_count - len(row))
        data.append(row)
    return data


def ips_to_list(s):
    # Конвертирование строки с IPs ranges в массив
    # input: '8.2.3.1-2,8.2.3.4-7,8.2.5.10'
    # return: ['8.2.3.1', '8.2.3.2', '8.2.3.4', '8.2.3.5', '8.2.3.6', '8.2.3.7', '8.2.5.10']
    ips_list = []
    for line in s.split(","):
        if "-" in line:
            ip_base = ".".join(line.split(".")[:3])
            ip_range = line.split(".")[-1]
            ip_begin, ip_end = map(int, ip_range.split("-"))
            for i in xrange(ip_begin, ip_end+1):
                ips_list.append(ip_base+"."+str(i))
        else:
            ips_list.append(line)
    return ips_list


def get_rdns_base_list(s):
    # Конвертирование строки с IPs ranges в rdns_nets list
    # input: '8.2.3.1-2,8.2.3.4-7,8.2.5.10'
    # return: ['8.2.3', '8.2.5']
    return list(set([".".join(ip.split(".")[:3]) for ip in s.split(",")]))


def get_dkim_key(domain):
    # Конвертирование DKIM public key в строку
    # input: 'domain.com'
    # return: MIGfMA0GCSqGSIb3DQEB......
    devnull = open(os.devnull, 'a')
    cmd = "openssl rsa -in " + global_path + dirs['dkim'] + domain + " -pubout -outform PEM"
    key = subprocess.check_output(cmd, shell=True, stderr=devnull)
    devnull.close()

    key = "".join(key.splitlines()[1:-1])
    return key


def make_private_dkim_keys(data):
    # Генерация приватных DKIM ключей
    devnull = open(os.devnull, 'a')
    for row in data:
        domain = row[data_map['domain']]
        cmd = "openssl genrsa -out " + global_path + dirs['dkim'] + domain + " 1024"
        # Генерить ключ если его нет
        if not os.path.exists(global_path + dirs['dkim'] + domain):
            subprocess.check_call(cmd, shell=True, stdout=devnull, stderr=devnull)
    devnull.close()


def generate_records(data):

    records = {}
    rev_records = {}
    pmta_conf = {}
    pmta_pref = {}
    for row in data:
        domain = row[data_map['domain']]
        records.setdefault(domain, [])

        if row[data_map['domain']]:
# SOA
            record = tmpl_soa.replace("__DATE__", datetime.datetime.now().strftime("%Y%m%d"))
            records[domain] += [record]
            if debug:
                with open(global_path + dirs['records'] + "SOA." + domain, 'a') as f:
                    f.write(record+'\n')

        if row[data_map['vpsip']]:
# NS
            record = tmpl_ns.replace('__VPS_IP__', row[data_map['vpsip']])
            records[domain] += [record]
            if debug:
                with open(global_path + dirs['records'] + "NS." + domain, 'a') as f:
                    f.write(record+'\n')
# A
            record = tmpl_a.replace('__VPS_IP__', row[data_map['vpsip']])
            records[domain] += [record]
            if debug:
                with open(global_path + dirs['records'] + "A." + domain, 'a') as f:
                    f.write(record+'\n')
# MX
            record = tmpl_mx.replace('__VPS_IP__', row[data_map['vpsip']])
            records[domain] += [record]
            if debug:
                with open(global_path + dirs['records'] + "MX." + domain, 'a') as f:
                    f.write(record+'\n')

        if row[data_map['sublink']]:
# SUB
            record = tmpl_sublink.replace('__SUB_LINK__', row[data_map['sublink']]).\
                replace('__VPS_IP__', row[data_map['vpsip']])
            records[domain] += [record]
            if debug:
                with open(global_path + dirs['records'] + "SUB." + domain, 'a') as f:
                    f.write(record+'\n')

        if row[data_map['fbl']]:
# FBL
            record = tmpl_fbl.replace('__SUB_FBL__', row[data_map['fbl']]). \
                replace('__VPS_IP__', row[data_map['vpsip']])
            records[domain] += [record]
            if debug:
                with open(global_path + dirs['records'] + "FBL." + domain, 'a') as f:
                    f.write(record + '\n')

        if row[data_map['spf']]:
# SPF
            record = tmpl_spf.replace('__SPF__', "ip4:" + " ip4:".join(row[data_map['spf']].split(",")))
            records[domain] += [record]
            if debug:
                with open(global_path + dirs['records'] + "SPF." + domain, 'a') as f:
                    f.write(record+'\n')

        if row[data_map['domain']]:
# DKIM
            record = tmpl_dkim.replace('__PUBLIC_DKIM_KEY__', get_dkim_key(domain)).replace('__DOMAIN__', domain)
            records[domain] += [record]
            if debug:
                with open(global_path + dirs['records'] + "DKIM." + domain, 'a') as f:
                    f.write(record+'\n')

        if row[data_map['rdns']]:

            for ip_base in get_rdns_base_list(row[data_map['rdns']]):
                rev_records.setdefault(ip_base, [])
# rSOA_NS
                record = tmpl_reverse.replace("__DATE__", datetime.datetime.now().strftime("%Y%m%d"))
                if not len(rev_records[ip_base]):  # Добавить SOA, только если ее не было
                    rev_records[ip_base] += [record]
                if debug:
                    with open(global_path + dirs['records'] + "rSOA_NS." + ip_base, 'a') as f:
                        f.write(record+'\n')

# gen rPTR A_PTR
            ptr_hash = {}
            a_list = []
            for ip in ips_to_list(row[data_map['rdns']]):

                ip_base = ".".join(ip.split(".")[:3])
                # Генерация постоянных-случайных префиксов в связке домен/подсеть
                random.seed(domain+ip_base)
                gw = random.choice(ptr_prefix_gw)
                srv = random.choice(ptr_prefix_srv)
                country = random.choice(ptr_country)

                #mlgw40.srv0.us.tritonchat.com.
                #ptr_domain=".".join([gw+ip.split(".")[-1], srv+ip.split(".")[-2], country, domain])+"."
		ptr_domain = ".".join([gw + ip.split(".")[-1], domain]) + "."
                #0.40.247.77.in-addr.arpa.
                ptr = ".".join(reversed(ip.split(".")))+".in-addr.arpa."

                record = tmpl_a_ptr.replace('__PTR_DOMAIN__', ptr_domain).replace('__PTR_IP__', ip)
                a_list += [record]

                record = tmpl_reverse_ptr.replace('__PTR__', ptr).replace('__PTR_DOMAIN__', ptr_domain)
                ptr_hash.setdefault(ip_base, [])
                ptr_hash[ip_base] += [record]

# Генерация массива данных для PMTA_conf
                if row[data_map['pmta_conf']]:
                    pmta_conf.setdefault(row[data_map['pmta_conf']],[])
                    pmta_conf[row[data_map['pmta_conf']]].append([ip, ptr_domain.rstrip("."), row[data_map['pmta_pref']]])
# {'conf_name': [['ip', 'ptr_domain', 'pref_name'],...] }

# Генерация массива данных для PMTA_pref
                    if not row[data_map['pmta_pref']]:
                        print "Имя pmta_prefs_name является обязательным для pmta_conf_name при генерации конфига pmta"
                        exit(1)
                    pmta_pref.setdefault(row[data_map['pmta_pref']],'')
                    pmta_pref[row[data_map['pmta_pref']]] = row[data_map['domain']]
# {'pref_name': 'dkim-identity domain', ... }
# dkim-identity domain - испозльуется если он есть в tmpl_pmta_pref, иначе - игнорируется

            for ip_base, ptr_list in ptr_hash.iteritems():
# rPTR
                rev_records[ip_base] += ["\n".join(ptr_list)]
                if debug:
                    with open(global_path + dirs['records'] + "rPTR." + ip_base, 'a') as f:
                        f.write("\n".join(ptr_list)+'\n')
# A_PTR
            records[domain] += ["\n".join(a_list)]
            if debug:
                with open(global_path + dirs['records'] + "A_PTR." + domain, 'a') as f:
                    f.write("\n".join(a_list)+'\n')

    if debug:
        for domain, rr_list in records.iteritems():
            with open(global_path + dirs['records'] + "ZONE." + domain, 'w') as f:
                f.write("\n\n".join(rr_list)+'\n')

        for rdns, rr_list in rev_records.iteritems():
            with open(global_path + dirs['records'] + "rZONE." + rdns, 'w') as f:
                f.write("\n\n".join(rr_list)+'\n')

    return records, rev_records, pmta_conf, pmta_pref


def build_named_conf(forw):
    for d in ["named/"]:
        if not os.path.exists(global_path+dirs['configs']+d):
            os.makedirs(global_path+dirs['configs']+d)
    for domain, rr_list in forw.iteritems():
        with open(global_path+dirs['configs']+"named/"+domain+".db", 'w') as f:
            f.write("\n\n".join(rr_list) + '\n')


def build_nsd_conf(forw, rev):
    for d in ["nsd/", "nsd/zones.bulk/", "nsd/zones.rev/"]:
        if not os.path.exists(global_path+dirs['configs']+d):
            os.makedirs(global_path+dirs['configs']+d)

    for domain, rr_list in forw.iteritems():
        with open(global_path+dirs['configs']+"nsd/zones.bulk/"+domain+".zone", 'w') as f:
            f.write("\n\n".join(rr_list) + '\n')

    for rdns, rr_list in rev.iteritems():
        with open(global_path+dirs['configs']+"nsd/zones.rev/net"+rdns+".zone", 'w') as f:
            f.write("\n\n".join(rr_list) + '\n')


def build_pmta_conf(data, pmta_conf, pmta_pref):
    for d in ["pmta/","pmta/customs/","pmta/domain.prefs/"]:
        if not os.path.exists(global_path+dirs['configs']+d):
            os.makedirs(global_path+dirs['configs']+d)

    for conf_name, configs in pmta_conf.iteritems():
        conf_list = []
        for i in configs:
            record = tmpl_pmta_conf.replace('__PTR_IP__', i[0]).replace('__PTR_DOMAIN__', i[1]).replace('__PREF__', i[2])
            conf_list += [record]
        with open(global_path + dirs['configs'] + "pmta/customs/" + conf_name + ".conf", 'w') as f:
            f.write("\n\n".join(conf_list) + '\n')

    for pref_name, dkim_domain in pmta_pref.iteritems():
        # dkim-identity domain - испозльуется если он есть в tmpl_pmta_pref, иначе - игнорируется
        record = tmpl_pmta_pref.replace('__DOMAIN__', dkim_domain)
        with open(global_path + dirs['configs'] + "pmta/domain.prefs/" + pref_name + ".conf", 'w') as f:
            f.write(record + '\n')
    # Копирование DKIM ключей для PMTA
    for row in data:
        domain = row[data_map['domain']]
        if os.path.exists(global_path+dirs['dkim']+domain):
            shutil.copy2(global_path+dirs['dkim']+domain, global_path+dirs['configs']+"pmta/customs/"+domain)


def print_named(data):
    print "==== Децентрализованый DNS ====\n"
    print "# NAMED: rsync /var/named/"
    print "# Добавляем на все VPS зоны"
    for row in data:
        ip = row[data_map['vpsip']]
        domain = row[data_map['domain']]
        print "rsync -avP "+global_path+dirs['configs']+"named/"+domain+".db "+ip+":/var/named/"+ domain+".db"
    print "\n# NAMED: /etc/named.newaje.zones"

    for ip in set(zip(*data)[data_map['vpsip']]):
     #   print "# Добавляем на VPS - " + ip
        for row in data:
            if row[data_map['vpsip']] == ip:
                domain = row[data_map['domain']]
                print "ssh " + ip + ' \'echo "zone \\\"' + domain + '.\\\" IN {type master; file \\\"' + domain + '.db\\\";};" >> /etc/named.newaje.zones\' </dev/null'
    print

def print_reverse_nsd():
    print "==== Обратные зоны  ====\n"
    print "# NSD: rsync /etc/nsd/zones.rev/"
    print "rsync -avP "+global_path+dirs['configs']+"nsd/zones.rev/ di132.ru.dcapi.net:/etc/nsd/zones.rev/"
    print "\n# NSD: reload"
    print "# ./1_genzoneconf - генерирует конфиг зон на основе файлов с зонами"
    print "root@di132:/home/shkrid# cd /etc/nsd"
    print "root@di132:/etc/nsd# ./1_genzoneconf"
    print "root@di132:/etc/nsd# ./2_checkconf"
    print "root@di132:/etc/nsd# ./3_reload"
    print

def print_nsd():
    print "==== Централизованый DNS ====\n"
    print "# NSD: rsync /etc/nsd/"
    print "rsync -avP "+global_path+dirs['configs']+"nsd/ di132.ru.dcapi.net:/etc/nsd/"
    print "\n# NSD: reload"
    print "# ./1_genzoneconf - генерирует конфиг зон на основе файлов с зонами"
    print "root@di132:/home/shkrid# cd /etc/nsd"
    print "root@di132:/etc/nsd# ./1_genzoneconf"
    print "root@di132:/etc/nsd# ./2_checkconf"
    print "root@di132:/etc/nsd# ./3_reload"
    print


def print_pmta(data, pmta_conf):
    print "==== PMTA ====\n"
    print "# PMTA: rsync /etc/pmta/"
    print "# Засинкать всю папку с конфигами на 1!!!!(один) необходимый PMTA"
    print "# rsync -avP " + global_path + dirs['configs'] + "pmta/ pmta.us.dcapi.net:/etc/pmta/"
    print "# rsync -avP " + global_path + dirs['configs'] + "pmta/ pmta1.us.dcapi.net:/etc/pmta/"
    print "# rsync -avP " + global_path + dirs['configs'] + "pmta/ pmta2.us.dcapi.net:/etc/pmta/"
    print "\n# Скопировать ключи на все PMTA и DMAN"
    print "rsync -avP --exclude '*.conf' " + global_path + dirs['configs'] + "pmta/customs/ pmta.us.dcapi.net:/etc/pmta/customs/"
    print "rsync -avP --exclude '*.conf' " + global_path + dirs['configs'] + "pmta/customs/ pmta1.us.dcapi.net:/etc/pmta/customs/"
    print "rsync -avP --exclude '*.conf' " + global_path + dirs['configs'] + "pmta/customs/ pmta2.us.dcapi.net:/etc/pmta/customs/"
    print "rsync -avP --exclude '*.conf' " + global_path + dirs['configs'] + "pmta/customs/ 67.207.165.90:/opt/warmer/spool/domainkeys/"
    print "\n# Добавить на всех PMTA конфиги ключей"
    print "cat <<EOF >> /etc/pmta/customs/dkim.conf"
    for domain in set(zip(*data)[data_map['domain']]):
        print "domain-key default,"+domain+",/etc/pmta/customs/"+domain
    print "EOF"
    print "\n# Подключить конфиги VMTA на 1!!!!(одном) необходимом PMTA"
    print "cat <<EOF >> /etc/pmta/config"
    for conf_name in pmta_conf:
        print "include /etc/pmta/customs/"+conf_name+".conf"
    print "EOF"
    print "\n# НЕ забыть сделать pmta reload !"

def print_postfix(data):
    # фильтр не пустых fbl
    fbl_data = filter(lambda item: item[data_map['fbl']], data)

    print "==== Postfix config on di132 ===="
    print "\n# locals"
    print "cat <<EOF >> /etc/postfix-bouncer/locals"
    for row in data:
        print row[data_map['domain']]
    print "EOF"
    print "\n# vhosts"
    print "cat <<EOF >> /etc/postfix-fbl/vhosts.txt"
    for row in fbl_data:
        print row[data_map['fbl']] + '.' + row[data_map['domain']]
    print "EOF"
    print "\n# valias"
    print "cat <<EOF >> /etc/postfix-fbl/valias.txt"
    for row in fbl_data:
        print "@" + row[data_map['fbl']] + '.' + row[data_map['domain']] + " yabuse,allabuse"
    print "EOF"
    print "\n#===Выполнить на di132===\ncd /etc/postfix-bouncer/\n./1_update\ncd /etc/postfix-fbl/\n./1_vhosts.sh\ncd /etc/postfix/\n./1_gen_transport"

clear_files(dirs)
create_dirs(dirs)

data_table = read_input_data()
make_private_dkim_keys(data_table)

forward, reverse, conf, pref = generate_records(data_table)
build_named_conf(forward)
build_nsd_conf(forward, reverse)
build_pmta_conf(data_table, conf, pref)

print_named(data_table)
#print_nsd()
print_reverse_nsd()
print_pmta(data_table,conf)
print_postfix(data_table)
