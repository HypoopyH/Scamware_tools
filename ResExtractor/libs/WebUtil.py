#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Dec 23 19:14:18 2020

@author: hypo
"""

import os
import re
import requests
import logging
import sys
import ssl
import subprocess

from Wappalyzer import Wappalyzer, WebPage
from urllib.parse import urlparse, urljoin

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(asctime)s: %(message)s", level=logging.INFO, datefmt='%a %d %b %Y %H:%M:%S')
log = logging.getLogger(__name__)

# To remove error.
# urllib.error.URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1123)>
ssl._create_default_https_context = ssl._create_unverified_context


class WebUtil:
    def __init__(self, url):
        self._url = url                         #
        self._is_active = None
        self._env = None
        self._init()

    def _init(self):
        proc = subprocess.Popen("wget --version", shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        r = (proc.communicate()[1]).decode()
        if r.find("not found") != -1:
            log.error("wget required.")
            self._env = False
            return
        else:
            self._env = True

        '''
        wget --spider --no-check-certificate https://wzpa2.lanchengzxl.com/1 
        '''
        proc = subprocess.Popen("wget --spider --timeout=10 --tries=3 --no-check-certificate {}".format(self._url), shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        r = (proc.communicate()[1]).decode()
        if r.find("200") == -1:
            log.error("server down.")
            self._is_active = False
        else:
            self._is_active = True

    @property
    def is_active(self):
        return self._is_active

    @property
    def server_info(self):
        '''
        get server information of the web server
        '''
        if not self._url.startswith('http'):
            url = "http://" + self._url
        else:
            url = self._url
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url, verify=False)
            return list(wappalyzer.analyze(webpage))
        except:
            return []

    @property
    def ip_info(self):
        """
        get domain information of the domain
        @ return ip, domain, math_location, location
        """
        gheaders = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"}
        domain = urlparse(self._url).netloc
        url = "https://ip.tool.chinaz.com/" + domain
        r = requests.get(url, headers=gheaders)
        if r.status_code != 200:
            return None, None, None, None
        r.encoding = r.apparent_encoding

        # t1[0]: ip
        # t2[0]: domain
        # t3[1]: MAC
        # t3[0]: MAC1

        t1 = re.findall('onclick=\"AiWenIpData\(\'(.*?)\'\)\">', r.text)
        t2 = re.findall('<span class=\"Whwtdhalf w15-0 lh45\">(.*?)<\/span>', r.text)
        t3 = re.findall('<span class=\"Whwtdhalf w30-0 lh24 tl ml80\">\s+<p>(.*?)<\/p>', r.text)

        if len(t2[0]) < 2:
            return t1[0], t2[0], None, t3[0]
        else:
            return t1[0], t2[0], t2[1], t3[0]

    def scarpy_web(self, storage_path):
        '''
        wget -r -l=1 --no-check-certificate -k --quota=20M https://wzpa2.lanchengzxl.com
        '''

        if self._env == False or self._is_active == False:
            log.error("crawl not satisfied")
            return False
        # caller should do this job
        if not os.path.isdir(storage_path):
            os.makedirs(storage_path)

        log.info("start crawling: {}".format(self._url))
        proc = subprocess.Popen("wget -r -l 1 --no-check-certificate -k --quota=20M {} -P '{}'".format(self._url, storage_path), shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _ = (proc.communicate()[0]).decode()

        log.info("finished")

        return True

if __name__ == "__main__":
    downloader = WebUtil("https://wzpa2.lanchengzxl.com")
    downloader.scarpy_web(os.path.join(os.path.dirname(__file__), "test"))
