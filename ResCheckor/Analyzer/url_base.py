# -*- coding: utf-8 -*-
"""
@author: Hypo
@file: url_base.py
@time: 2020-12-11 11:29
"""
from treelib import Tree
from bs4 import BeautifulSoup
import bs4
import time
import ssl
import urllib.request
import urllib.parse
import re
import sys
import os
import csv


class Converter:
    def __init__(self, dom_tree, dimension):
        self.dom_tree = dom_tree
        self.node_info_list = []
        self.dimension = dimension
        self.initial_weight = 1
        self.attenuation_ratio = 0.6
        self.dom_eigenvector = {}.fromkeys(range(0, dimension), 0)

    def get_eigenvector(self):
        for node_id in range(1, self.dom_tree.size() + 1):
            node = self.dom_tree.get_node(node_id)
            node_feature = self.create_feature(node)
            feature_hash = self.feature_hash(node_feature)
            node_weight = self.calculate_weight(node, node_id, feature_hash)
            self.construct_eigenvector(feature_hash, node_weight)
        return self.dom_eigenvector

    @staticmethod
    def create_feature(node):
        node_attr_list = []
        node_feature = node.data.label + '|'
        for attr in node.data.attrs.keys():
            node_attr_list.append(attr + ':' + str(node.data.attrs[attr]))
        node_feature += '|'.join(node_attr_list)
        return node_feature

    @staticmethod
    def feature_hash(node_feature):
        return abs(hash(node_feature)) % (10 ** 8)

    def calculate_weight(self, node, node_id, feature_hash):
        brother_node_count = 0
        depth = self.dom_tree.depth(node)
        for brother_node in self.dom_tree.siblings(node_id):
            brother_node_feature_hash = self.feature_hash(
                self.create_feature(brother_node))
            if brother_node_feature_hash == feature_hash:
                brother_node_count = brother_node_count + 1
        if brother_node_count:
            node_weight = self.initial_weight * self.attenuation_ratio ** depth * \
                self.attenuation_ratio ** brother_node_count
        else:
            node_weight = self.initial_weight * self.attenuation_ratio ** depth
        return node_weight

    def construct_eigenvector(self, feature_hash, node_weight):
        feature_hash = feature_hash % self.dimension
        self.dom_eigenvector[feature_hash] += node_weight


class DOMTree:
    def __init__(self, label, attrs):
        self.label = label
        self.attrs = attrs


class HTMLParser:

    def __init__(self, html):
        self.dom_id = 1
        self.dom_tree = Tree()
        self.bs_html = BeautifulSoup(html, 'lxml')

    def get_dom_structure_tree(self):
        for content in self.bs_html.contents:
            if isinstance(content, bs4.element.Tag):
                self.bs_html = content
        self.recursive_descendants(self.bs_html, 1)
        return self.dom_tree

    def recursive_descendants(self, descendants, parent_id):
        if self.dom_id == 1:
            self.dom_tree.create_node(descendants.name, self.dom_id, data=DOMTree(
                descendants.name, descendants.attrs))
            self.dom_id = self.dom_id + 1
        for child in descendants.contents:
            if isinstance(child, bs4.element.Tag):
                self.dom_tree.create_node(
                    child.name, self.dom_id, parent_id, data=DOMTree(child.name, child.attrs))
                self.dom_id = self.dom_id + 1
                self.recursive_descendants(child, self.dom_id - 1)


def calculated_similarity(dom1_eigenvector, dom2_eigenvector, dimension):
    a, b = 0, 0
    for i in range(dimension):
        a += dom1_eigenvector[i]-dom2_eigenvector[i]
        if dom1_eigenvector[i] and dom2_eigenvector[i]:
            b += dom1_eigenvector[i] + dom2_eigenvector[i]
    similarity = abs(a)/b
    return similarity


def get_html_similarity(html_doc1, html_doc2, dimension=5000):
    hp1 = HTMLParser(html_doc1)
    html_doc1_dom_tree = hp1.get_dom_structure_tree()
    hp2 = HTMLParser(html_doc2)
    html_doc2_dom_tree = hp2.get_dom_structure_tree()
    converter = Converter(html_doc1_dom_tree, dimension)
    dom1_eigenvector = converter.get_eigenvector()
    converter = Converter(html_doc2_dom_tree, dimension)
    dom2_eigenvector = converter.get_eigenvector()
    value = calculated_similarity(
        dom1_eigenvector, dom2_eigenvector, dimension)
    if value > 0.2:
        return False, value
    else:
        return True, value


"""
Get URL feature 
store in dimension dataset
"""


def get_html_info(html, dimension=5000):
    hp1 = HTMLParser(html)
    html_doc1_dom_tree = hp1.get_dom_structure_tree()
    converter = Converter(html_doc1_dom_tree, dimension)
    dom1_eigenvector = converter.get_eigenvector()

    return dom1_eigenvector


"""
The Core url similarity compare function
Input should be two list, have the same dimension
"""


def cal_html_similarity(list1, list2, dimension=5000):
    value = calculated_similarity(list1, list2, dimension)
    if value > 0.2:
        return False, value
    else:
        return True, value


def add_parameters(params, **kwargs):
    "parms producer"
    params.update(kwargs)


def url_filter(url,filter):
    """
        filter can refer to the top 1w weblist by alexa
        or some special string ——such as github/fjson?.
        whatever filter should be a list
    """
    for i in filter:
        if i in url:
            return True
    return False



def url_alive(url):
    """
        To detect the url weather still achievable
    """
    try:
        response = urllib.request.urlopen(url,timeout=3)
    except IOError:
        return False
    except ssl.CertificateError:
        return False
    else:
        code = response.getcode()
        if code == 404:
            return False
        elif code == 403:
            return False
        else:
            return True


class HTML:
    def __init__(self, URL, ifip=False, dimension=5000):
        self.__URL = URL
        self.__isip = ifip
        self.__content = None
        self.__feature = None
        self.__alive = None
        self.__dimension = dimension

    @property
    def getname(self):
        """
        get url
        """
        return self.__URL

    @property
    def ifip(self):
        """
        check if ip or url
        """
        return self.__isip

    @property
    def topdomain(self):
        """
        get top level domain
        """
        if self.getname.count("/") >=3:
            return re.findall('https?://(.*?)/', self.getname)[0]
        return self.getname

    @property
    def alive(self):
        """
        test if the url is alive
        """
        if self.__alive == None:
            try:
                response = urllib.request.urlopen(self.getname)
            except IOError:
                self.__alive == False
                return False
            except ssl.CertificateError:
                self.__alive == False
                return False
            else:
                code = response.getcode()
                if code == 404:
                    self.__alive == False
                    return False
                elif code == 403:
                    self.__alive == False
                    return False
                else:
                    self.__alive == True
                    return True
        return self.__alive

    @property
    def get_content(self):
        """
        get content
        """
        if self.alive == True and self.__content == None:
            self.__content = urllib.request.urlopen(
                self.__URL).read().decode('UTF-8')
        return self.__content

    @property
    def url_feature(self):
        """
        get feature
        """
        if self.alive == True and self.__feature == None:
            self.__feature = get_html_info(self.get_content, self.__dimension)
        return self.__feature

    @property
    def img_list(self):
        """
        return the img file list,but not img formal
        """
        if self.alive == True:
            img=[]
            res=[]
            img.extend(self.regexcheck("src=\"(.+?\.jpg)\" "))
            img.extend(self.regexcheck("src=\"(.+?\.png)\" "))
            for i in img:
                img_add=urllib.parse.urljoin(self.getname,i)
                res.append(img_add)
            return res
        return None
    
    def download_img(self, path):
        """
        download the img to local
        """
        img = self.img_list
        if img == None:
            print("no img")
            return
        if not os.path.isdir(path):
            os.makedirs(path)
            paths = path+"\\"
        x=0
        for i in img:
            try:
                if i.endwith(".jpg"):
                    urllib.request.urlretrieve(img_add,'{}{}.jpg'.format(paths,x))
                else:
                    urllib.request.urlretrieve(img_add,'{}{}.png'.format(paths,x))
                x+=1
            except:
                print("download error")

    def url_similarity(self, url2):
        """
        Get the similarity with url2
        """
        if self.url_feature != None and url2.url_feature != None:
            return calculated_similarity(self.url_feature, url2.url_feature, self.__dimension)
        return None

    def db_similarity(self, dom1_eigenvector):
        """
        Get the similarity with dblist
        """
        if self.url_feature != None:
            return calculated_similarity(self.url_feature, dom1_eigenvector, self.__dimension)

    def regexcheck(self, regex):
        """
        Find a regex in html.
        """
        result = []
        text = self.get_content
        r = re.compile(regex)
        result.extend(r.findall(text))
        return result

    def domain_check(self, balcklist, whitelist):
        """
        check if domain in whitelist or blacklist
        """
        if self.topdomain in whitelist:
            return True
        elif self.topdomain in balcklist:
            return False
        else:
            return None


def test():
    htest = HTML("https://www.runoob.com/python3/python3-string-endswith.html")
    #print(htest.alive)
    #print(htest.getname)
    #print(htest.get_content)
    #print(htest.img_list)
    #print(htest.url_feature[1])
    print(htest.topdomain)


if __name__== "__main__":
    test()
