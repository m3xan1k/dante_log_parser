#!/usr/bin/env python3

import re
from collections import Counter
import csv

def reader(filename):

    regexp_ip = r'\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}'

    with open(filename, 'r') as f:
        log = f.read()

        ips_list_with_server = re.findall(regexp_ip, log)
        ips_list = []

        for ip in ips_list_with_server:
            if ip != '79.137.35.113':
                ips_list.append(ip)


    return ips_list

def count(ips_list):
    count = Counter(ips_list)
    return count

def write_csv(count):

    with open('log.csv', 'w') as csvfile:
        writer = csv.writer(csvfile)

        header = ['IP', 'Frequency']
        writer.writerow(header)

        for item in count:
            writer.writerow( (item, count[item]) )

def parse_username(filename):
    regexp = r'%\w+'
    with open(filename, 'r') as f:
        log = f.read()
        usernames = re.findall(regexp, log)
    print(usernames)

def parse_month(filename):
    regexp_month = r'^\w+'
    months = []
    with open(filename, 'r') as f:
        for line in f:
            month_object = re.search(regexp_month, line)
            month = month_object.group()
            if month not in months:
                months.append(month)
    print(months)

def parse_date_time(filename):
    regexp = r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}'
    with open(filename, 'r') as f:
        log = f.read()
        dates = re.findall(regexp, log)
    print(dates)

def parse_users(filename):
    date = 'Apr 16'
    regexp_date = r'[JFMASOND]\w+ \d{1,2}'
    regexp_ip = r'(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})'
    regexp_username = r'%\w+'
    ips_users = []
    ips_scum = []
    with open(filename, 'r') as f:
        for line in f:
            # print(line)
            # if re.match(date, line):
            #     print('date is ok')
            if 'tcp/connect' in line:
                try:
                    ip_object = re.search(regexp_ip, line)
                    ip = ip_object.group()
                    username_object = re.search(regexp_username, line)
                    username = username_object.group().replace('%', '')
                    data = (ip, username)
                    ips_users.append(data)
                except AttributeError:
                    ip_object = re.search(regexp_ip, line)
                    ip = ip_object.group()
                    username = 'unauthorized'
                    data = (ip, username)
                    ips_users.append(data)

    count = Counter(ips_users).most_common(10)

    print(count)

def parse_unauthorized(filename):
    regexp_ip = r'(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})'
    regexp_username = r'%\w+'
    ips_scum = []
    with open(filename, 'r') as f:
        for line in f:
            if 'system username/password failed' in line:
                try:
                    ip_object = re.search(regexp_ip, line)
                    ip = ip_object.group()
                    username_object = re.search(regexp_username, line)
                    username = username_object.group().replace('%', '')
                    data = (ip, username)
                    ips_scum.append(data)
                except AttributeError:
                    ip_object = re.search(regexp_ip, line)
                    ip = ip_object.group()
                    username = 'unauthorized'
                    data = (ip, username)
                    ips_scum.append(data)

    count = Counter(ips_scum).most_common(10)

    print(count)

def parse_days(filename, month):
    regexp_days =r'\w{3}\s{1,2}\d{1,2}'
    print(regexp_days)
    days = []
    with open(filename, 'r') as f:
        for line in f:
            if month in line:
                print(line)
                day_object = re.search(regexp_days, line)
                day = day_object.group()
                if day not in days:
                    days.append(day)
    print(days)

def main():
    # write_csv(count(reader('socks.log')))
    # parse_username('socks.log')
    # parse_users('socks.log')
    # parse_unauthorized('socks.log')
    # parse_days('socks.log', 'Apr')
main()
