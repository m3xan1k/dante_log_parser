#!/usr/bin/env python3

import re
from collections import Counter, OrderedDict
from flask import Flask
from flask import render_template
import sys
import os
from functools import wraps
from flask import request, Response
import json

# os.chdir('/path/where/app/is')

app = Flask(__name__)

filename = sys.argv[1]

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    # you need to create a json file with your login/pw data or you can create some other method to authenticate
    with open('nothing.json') as f:
        data = json.load(f)
    username = data['username']
    password = data['password']
    return username, password

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/')
@requires_auth
def index():
    months = parse_month(filename)
    return render_template('index.html', months=months)

@app.route('/top')
@requires_auth
def top():
    count = count_top(filename)
    return render_template('top.html', count=count)

@app.route('/<string:month>')
@requires_auth
def month(month):
    days = parse_days(filename, month)
    return render_template('month.html', days=days, month=month)

@app.route('/<string:month>/<string:day>')
@requires_auth
def day(month, day):
    not_authentic = no_authentication(filename, month, day)
    password_fail = password_failed(filename, month, day)
    connections = passed_connections(filename, month, day)
    days = parse_days(filename, month)
    return render_template('day.html', days=days, day=day, not_authentic=not_authentic, password_fail=password_fail, connections=connections, month=month)



def parse_month(filename):
    regexp_month = r'^\w+'
    months = []
    with open(filename, 'r') as f:
        for line in f:
            month_object = re.search(regexp_month, line)
            month = month_object.group()
            if month not in months:
                months.append(month)
    return months

def parse_days(filename, month):
    regexp_days =r'\w{3}\s{1,2}\d{1,2}'
    days = {}
    with open(filename, 'r') as f:
        i = 1
        for line in f:
            if month in line:
                day_object = re.search(regexp_days, line)
                day = day_object.group()
                if day not in days.values():
                    days[i] = day
                    i += 1
    return days

def no_authentication(filename, month, day):
    regexp_ip = r'(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})'
    ips = []
    with open(filename, 'r') as f:
        for line in f:
            if day in line:
                if 'no acceptable authenticationmethod' in line:
                    ip_object = re.search(regexp_ip, line)
                    ip = ip_object.group()
                    username = 'no authentication'
                    data = (ip, username)
                    ips.append(data)

    count = Counter(ips).most_common(10)

    return count

def password_failed(filename, month, day):
    regexp_ip = r'(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})'
    regexp_username = r'%\w+'
    ips = []
    with open(filename, 'r') as f:
        for line in f:
            if day in line:
                if 'password failed' in line:
                    try:
                        ip_object = re.search(regexp_ip, line)
                        ip = ip_object.group()
                        username_object = re.search(regexp_username, line)
                        username = username_object.group().replace('%', '')
                        data = (ip, username)
                        ips.append(data)
                    except AttributeError:
                        ip_object = re.search(regexp_ip, line)
                        ip = ip_object.group()
                        username = 'no name'
                        data = (ip, username)
                        ips.append(data)

    count = Counter(ips).most_common(10)

    return count

def passed_connections(filename, month, day):
    regexp_ip = r'(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})'
    regexp_username = r'%\w+'
    regexp_bytes = r'\:\s\d+\s'
    ips = []
    with open(filename, 'r') as f:
        for line in f:
            if day in line:
                if 'pass(1): tcp/connect' in line:
                    ip_object = re.search(regexp_ip, line)
                    ip = ip_object.group()
                    try:
                        username_object = re.search(regexp_username, line)
                        username = username_object.group().replace('%', '')
                    except AttributeError:
                        username = 'not parsed'
                    try:
                        bytes_object = re.search(regexp_bytes, line)
                        bytes = bytes_object.group().replace(':', '').strip()
                        bytes = int(bytes) / 1048576
                    except AttributeError:
                        bytes = 0
                    data = ((ip, username), bytes)
                    ips.append(data)

    all_dict = {}
    for entry in ips:
        ip = entry[0][0]
        username = entry[0][1]
        bytes = entry[1]
        params = {"username": username, "megabytes": bytes, "connections": 1}
        if ip not in all_dict.keys():
            all_dict[ip] = params
        else:
            all_dict[ip]["megabytes"] += bytes
            all_dict[ip]["connections"] += 1

    # print(all_dict)

    megabytes = []
    for ip in all_dict:
        megabytes.append(all_dict[ip]["megabytes"])
    megabytes.sort()
    megabytes.reverse()

    # print(megabytes)

    sorted_dict = OrderedDict()

    for value in megabytes:
        for element in all_dict:
            if value == all_dict[element]["megabytes"]:
                sorted_dict[element] = all_dict[element]

    return sorted_dict


def count_top(filename):
    regexp_ip = r'(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})'
    ips = []
    with open(filename) as f:
        for line in f:
            try:
                ip_object = re.search(regexp_ip, line)
                ip = ip_object.group()
                ips.append(ip)
            except AttributeError:
                pass

    count = Counter(ips).most_common(20)

    return count

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5432)
