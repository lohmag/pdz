#!/usr/bin/env python
# -*- coding: utf-8 -*-

# DNS FORWARD
tmpl_soa = '''$TTL 300
@ IN SOA ns1 root ( __DATE__01 28800 7200 604800 86400 )'''

tmpl_ns = '''@ IN NS ns1
@ IN NS ns2
ns1 IN A __VPS_IP__
ns2 IN A __VPS_IP__'''

tmpl_a = '''@ IN A __VPS_IP__'''

tmpl_mx = '''@ IN MX 10 mx
mx IN A __VPS_IP__'''

tmpl_sublink = '''__SUB_LINK__ IN A __VPS_IP__'''

tmpl_fbl = '''__SUB_FBL__ IN A __VPS_IP__
__SUB_FBL__ IN MX 10 __SUB_FBL__'''

tmpl_spf = '''@ TXT "v=spf1 __SPF__ -all"'''

tmpl_dkim = '''_domainkey IN TXT "t=s; o=-"
default._domainkey IN TXT "k=rsa; t=s; p=__PUBLIC_DKIM_KEY__;"
_dmarc IN TXT "v=DMARC1; p=reject; ruf=mailto:dmarcsupport@__DOMAIN__; rua=mailto:dmarcsupport@__DOMAIN__"'''

tmpl_a_ptr = '''__PTR_DOMAIN__ IN A __PTR_IP__'''

# DNS REVERSE
tmpl_reverse = '''$TTL 300
@ IN SOA dns8.di-net.ru. root.di-net.ru. ( __DATE__01 28800 7200 604800 86400 )

@ IN NS dns8.di-net.ru.
@ IN NS dns9.di-net.ru.'''

tmpl_reverse_ptr = '''__PTR__ IN PTR __PTR_DOMAIN__'''

# PMTA CONFIGS
tmpl_pmta_conf = '''<virtual-mta __PTR_IP__>
    smtp-source-host __PTR_IP__ __PTR_DOMAIN__
    include /etc/pmta/domain.prefs/__PREF__.conf
</virtual-mta>'''

# Темплайт для RAMBLERа где необходимо подставлять dkim-identity
# Иначе необходимо убрать dkim-identity из темлайта
tmpl_pmta_pref = '''<domain $Yahoo>
      max-smtp-out    1        # max. connection
      max-msg-per-connection 1
      dkim-sign yes
      max-msg-rate 50/h
      retry-after     5s        # 1 hour
      bounce-after 72h
      bounce-upon-5xx-greeting false
      deliver-local-dsn no
      use-starttls true
      require-starttls false
      smtp-pattern-list sergey-pattern
      dkim-identity @__DOMAIN__
</domain>
<domain $Gmail>
      dkim-sign yes
      max-msg-rate 2000/h
      retry-after     10m        # 1 hour
      bounce-after 72h
      bounce-upon-5xx-greeting false
      deliver-local-dsn no
      use-starttls true
      require-starttls false
      dkim-identity @__DOMAIN__
</domain>

<domain $Hotmails>
      dkim-sign yes
      max-msg-rate 800/h
      retry-after     10m        # 1 hour
      bounce-after 72h
      bounce-upon-5xx-greeting false
      deliver-local-dsn no
      use-starttls true
      require-starttls false
      dkim-identity @__DOMAIN__
</domain>

<domain $AOL>
      dkim-sign yes
      max-msg-rate 800/h
      retry-after     10m        # 1 hour
      bounce-after 72h
      bounce-upon-5xx-greeting false
      deliver-local-dsn no
      use-starttls true
      require-starttls false
      dkim-identity @__DOMAIN__
</domain>

<domain $mailru>
      max-smtp-out 10
      max-msg-per-connection 1
      dkim-sign yes
      max-msg-rate 55/h
      retry-after 10m
      bounce-after 72h
      bounce-upon-5xx-greeting true
      deliver-local-dsn no
      use-starttls true
      require-starttls false
      dkim-identity @__DOMAIN__
</domain>

<domain $ramblers>
      max-smtp-out    20        # max. connection
      max-msg-per-connection 20
      dkim-sign yes
      max-msg-rate 2000/h
      retry-after     10m        # 1 hour
      bounce-after 72h
      bounce-upon-5xx-greeting false
      deliver-local-dsn no
      use-starttls true
      require-starttls false
      dkim-identity @__DOMAIN__
</domain>

<domain [*.]yandex.ru>
      dkim-sign yes
      max-msg-rate 2000/h
      retry-after     5m        # 1 hour
      bounce-after 72h
      bounce-upon-5xx-greeting false
      deliver-local-dsn no
      use-starttls true
      require-starttls false
      dkim-identity @__DOMAIN__
</domain>

<domain *>
      dkim-sign yes
      max-msg-rate 50/h
      max-smtp-out 10
      retry-after     10m        # 1 hour
      bounce-after 72h
      bounce-upon-5xx-greeting false
      deliver-local-dsn no
      use-starttls true
      require-starttls false
      dkim-identity @__DOMAIN__
</domain>'''
