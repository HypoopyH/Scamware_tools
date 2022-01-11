#!/usr/bin/env python
# coding: utf-8

# In[128]:


# coding=utf-8
'''
IP反查小工具
https://site.ip138.com/xxxx
'''
import requests
import json
import urllib
import sys
import os
from bs4 import BeautifulSoup
import re


def check_domain(ip):
    """
    检查输入的域名格式
    http://wuyu.fxtmets3.cc/wap/main.html改为wuyu.fxtmets3.cc
    """
    if('http' in ip):
        ip = re.findall('https?:\/\/(.*?)\/', ip)[0]
    return ip


def getPage(ip, web):
    qheaders = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"}
    ip = check_domain(ip)
    url = web+ip
    print(url)
    r = requests.get(url, headers=qheaders)
    r.encoding = r.apparent_encoding
    return r.text


def getPage_sel(ip):
    qheaders = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"}
    url = "https://site.ip138.com/"+ip+'/'
    print(url)
    r = requests.get(url, headers=qheaders)
    res = re.findall('<li><span class=\"date\">(.*)?</li>', r.text)
    params = {}
    params['time'] = []
    params['domain'] = []
    number = 0
    for i in res:
        number += 1
        time = re.findall('(.*)</span>', i)
        domain = re.findall('a href=\"\/(.*)?\" target', i)
        params['time'].append(time)
        params['domain'].append(domain)
    return params


def Domain_get_IP(ip):
    """
    域名的IP，地理位置
    """
    dicts = {}
    text = getPage(ip, "https://ip.tool.chinaz.com/")
    domain = re.findall('<span class=\"Whwtdhalf w15-0\">(.*?)<\/span>', text)
    ips = re.findall('onclick=\"AiWenIpData\(\'(.*?)\'\)\">', text)
    dicts['IP'] = ips[0]
    dicts['domain'] = domain[3]
    dicts['math_location'] = domain[4]
    result = re.findall('<span class=\"Whwtdhalf w50-0\">(.*?)<\/span>', text)
    dicts['location'] = result[1]
    print(dicts)
    return dicts


def IP_get_Domain(ip):
    """
    IP反查询域名
    """
    dicts = {}
    text = getPage_sel(ip)
    print(text)
    return dicts


def Whois(ip, web="http://whois.chinaz.com/"):
    """
    查询注册人、注册邮箱、
    """

    dicts = {}
    text = getPage(ip, web)
    registrar = re.findall('Registrar: (.*?)<', text)[0]
    email = re.findall('Registrar Abuse Contact Email: (.*?)<', text)[0]
    dicts['registrar'] = registrar
    dicts['email'] = email

    return dicts


if __name__ == "__main__":
    ip = '107.6.242.85'
    IP_get_Domain(ip)
    domain = 'http://wuyu.fxtmets3.cc/wap/main.html'
    Domain_get_IP(domain)
    Whois("http://wuyu.fxtmets3.cc/wap/main.html")
