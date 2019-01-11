
Необходимо сформировать таблицу со следующимии столбцами:

- `*` domain - домен

- `*` vpsip - ип адрес впс-сервера

- sublink - имя саб-линка

- fbl - имя фбл записи

- spf - необходимая спф сетка (одиночный ип или подсеть, например **77.247.42.10,77.247.42.0/25**)

- rdns - диапазон для rdns (одиночный ип или диапазон, например **77.247.40.1-5,77.247.41.50-55**)

- pmta_conf - название пулла

- pmta_pref - название конфига для пулла


`*` - обязательные поля

**пример таблицы**

| domain           | vpsip           | sublink | fbl      | spf                        | rdns                       | pmta_conf         | pmta_pref             |
|------------------|-----------------|---------|----------|----------------------------|----------------------------|-------------------|-----------------------|
| pagetoknight.com | 77.244.215.105  | ccwte   | loop     | 77.247.48.0/25,77.247.52.1 | 77.247.48.1-5,77.247.48.15 | rambler.77.247.48 | serg-gray-77.247.48-1 |
| girardhotels.com | 104.131.191.172 | sjmma   | fbl      | 77.247.48.128/25           | 77.247.48.6-10             | rambler.77.247.48 | serg-gray-77.247.48-2 |
| norakitty.com    | 95.213.194.11   | uihxe   | feedback | 77.247.50.0/25             |                            |                   |                       |
| nanokiss.com     | 139.162.233.199 | onflf   | loop     |                            |                            |                   |                       |
| texaslambdas.com | 77.244.215.105  | qjefg   |          |                            |                            |                   |                       |
| mantramonkey.com | 104.131.191.172 |         |          |                            |                            |                   |                       |



Данные из таблицы вставить в **input_table.txt**



```

tree
.
├── README.md
├── config.py
├── config.pyc
├── configs
│   ├── named
│   │   ├── girardhotels.com.db
│   │   ├── mantramonkey.com.db
│   │   ├── nanokiss.com.db
│   │   ├── norakitty.com.db
│   │   ├── pagetoknight.com.db
│   │   └── texaslambdas.com.db
│   ├── nsd
│   │   ├── zones.bulk
│   │   │   ├── girardhotels.com.zone
│   │   │   ├── mantramonkey.com.zone
│   │   │   ├── nanokiss.com.zone
│   │   │   ├── norakitty.com.zone
│   │   │   ├── pagetoknight.com.zone
│   │   │   └── texaslambdas.com.zone
│   │   └── zones.rev
│   │       └── net77.247.48.zone
│   └── pmta
│       ├── customs
│       │   ├── girardhotels.com
│       │   ├── mantramonkey.com
│       │   ├── nanokiss.com
│       │   ├── norakitty.com
│       │   ├── pagetoknight.com
│       │   ├── rambler.77.247.48.conf
│       │   └── texaslambdas.com
│       └── domain.prefs
│           ├── serg-gray-77.247.48-1.conf
│           └── serg-gray-77.247.48-2.conf
├── input_table.txt
├── input_table.txt.example
├── keys
│   ├── girardhotels.com
│   ├── mantramonkey.com
│   ├── nanokiss.com
│   ├── norakitty.com
│   ├── pagetoknight.com
│   └── texaslambdas.com
└── pdz.py

9 directories, 34 files

```

Папка `keys/` всегда хранит все ключи. Если их там нет при генерации - то они создаются. Если есть - используются существующие.
Соответственно можно подкидывать в нее ключи и на основе них будут сгенерированы публичные ключи.
