# -*- coding: utf-8 -*-
"""
@author: Hypo
@file: url_base.py
@time: 2020-12-11 11:29
"""


import os
import sys
import json
sys.path.append("..")
from Analyzer.url_base import *
from Analyzer.analyzer_base import *

"""
Top DESIGN
input:
    URL list
output:
    Safe,benign,unkown,illegal
"""


def read_config(config='config.json'):
    with open(config, 'r') as f:
        data = json.load(f)
        return data


def find_keyword(content, keywordlist):
    return sum([1 if w in content else 0 for w in keywordlist])


def get_db_feature(url: HTML, config):
    session = create_session(
        config["dbtype"], config['Username'], config['Password'], 'localhost', config['collection'])
    """database not decided yet
    MYSQL = "select id from %s where %s=\"%s\"" % (
                            tables, ids, value)
    result = session.execute(MYSQL).fetchall()
    score = max([url.db_similarity()])
    return score
    """
    pass

def login_judge(url:HTML):
    text = url.get_content
    if('登录' in text and "输入账号" in text and "输入密码" in text) or "注册" in text:
        return True
    return False


def url_judge(url_list,configfile='config.json'):
    judge_list=[]
    for url in url_list:
        html = HTML(url)
        if(html.alive != True):
            judge_list.append(["dead","dead"])
            continue
        config = read_config(configfile)
        "in top 1w alexa, we think they are safe"
        if(url_filter(html.getname, config["CNfilter"]) == True or url_filter(html.getname, config["USfilter"]) == True):
            judge_list.append(["Safe","whitelist"])
            continue

        """NOT IMPLEMENT
        This section introduces a blacklist,  which of course should not be too large
        """
        flag = False
        "if the url content has illegal keywords, we think it's illegal"
        for f in config["Keyword_file_list"]:
            fo = open(f, 'r').encode('utf-8')
            keywordlist = fo.readlines()
            fo.close()
            if(find_keyword(html.get_content, keywordlist) == True):
                types = re.search("\/(.*).txt",f).group(0)
                judge_list.append(["illegal",types])
                flag = True
                continue
        if(flag == True):
            continue

        """NOT IMPLEMENT
        at this steop, we can't find any keyword or in backlist whitlist
        we guess this is because lot's of illegal app need login
        There is no other plan, we had to search our own html feature database
        """
        if(get_db_feature(html, config) > 0.5):
            #此处阈值自己设计
            judge_list.append(["illegal",types])
            continue

        
        """NOT IMPLEMENT
        icon judge maybe?
        """

        if(login_judge(html)==False):
            judge_list.append(["benign","benign"])
            continue
        else:
            judge_list.append(["unknown","unknown"])
            continue

    return judge_list


if __name__ == "__main__":
    url_judge(["www.baidu.com", "www.google.com"])
