#!/usr/bin/env python
from lxml import html
import requests
from bs4 import BeautifulSoup

url = "https://learn.microsoft.com/en-us/windows/release-health/release-information"

import csv
from datetime import datetime
import sqlite3

def extract_date(s):
    start = s.find("(")
    end = s.find(")")
    d_str = s[start+1:end]
    d = datetime.strptime(d_str, "%M %b %Y")
    return d

results = []
#results.append(["Release", "Released", "Active Support", "Security Support", "Build"])

with open('/home/cb/PycharmProjects/Testdata/eol-list.csv') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    for row in csv_reader:
        release = row['Release']
        released=extract_date(row['Released'])
        active=extract_date(row['Active Support'])
        security=extract_date(row['Security Support'])
        build=row['Latest']

        results.append([release,released,active,security,build])

with open('/home/cb/PycharmProjects/Testdata/eol-list-output.csv', 'w') as f:
    writer = csv.writer(f)
    for r in results:
        writer.writerow(r)