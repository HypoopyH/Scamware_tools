import json
from sqlalchemy import func
import argparse
import sys
import os

sys.path.append("../Analyzer")
from analyzer_base import *
sys.path.append("../APK_parser")
from basic_parser import *
from dbout import *
sys.path.append("../DownloadAPI")
from koodous import *

def Analyzer_engine(inputdir, limit, config):
    """
        核心分析部分，入库部分
        """
    session = create_session('mysql', config.get("Username"), config.get(
        "Password"), 'localhost', 'OldMoney_test')

    beginID = session.query(func.count(APKfile.id)).scalar()
    session.close()
    runner = Runner([DirInput(inputdir)], limit=limit,save_period=5)
    runner.add_analyzer(BasicInfoAnalyzer)
    runner.add_output(DBinfoOutput())
    runner.run()

    session = create_session('mysql', config.get("Username"), config.get(
        "Password"), 'localhost', 'OldMoney_test')
    endID = session.query(func.count(APKfile.id)).scalar()
    session.close()
    print(beginID, endID)
    return beginID, endID


"""
目前仍然未解决依赖爆炸问题，并且如果搜索结果大于1000个的文件夹限制，也没有做好文件夹切割
"""


def Cluster_engine(outputdir, begin, end, config):
    """
    核心关联部分，通过Koodous等下载更多APK
    """
    session = create_session('mysql', config.get("Username"), config.get(
        "Password"), 'localhost', 'OldMoney_test')
    """
    demo版本先只考虑StaticInfo,然后查询属性这里引入了json的方法自定义
    【注】本demo目前操作，只实现Koodous中所包含的有效键查询
    """
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    num = 0
    table = config.get("Table_List")
    for coon in table.values():
        table = coon["name"]
        for item in coon["items"]:
            """
            此处通过group by去除重复内容
            """
            MYSQL = "select %s from %s where id>%d and id<=%d group by %s" % (
                item, table, begin, end, item)
            result = session.execute(MYSQL).fetchall()

            for param in result:
                for name, value in param.items():
                    if (value is not None) and value != "NULL":
                        apks = search(search_term=value, limit=1000)
                        result = {
                            "term": value,
                            "results": apks
                        }
                        print("Search '%s' returned %d results." %
                              (value, len(apks)))
                        outfile = outputdir+'/'+str(num)+'.json'
                        json.dump(result, open(outfile, "w"), indent=2)
                        num = num+1

    """
    下载
    """
    for i in range(0, num):
        jsonfile = outputdir+'/'+str(i)+'.json'
        data = json.load(open(jsonfile, 'r'))
        apks = data.get("results", [])
        for apk in apks:
            md5 = apk["md5"]
            if session.query(func.count(APKfile.md5)).filter(APKfile.md5 == md5).scalar() > 0:
                print("md5 %s exists." % md5)
            else:
                ret = download_single(apk["sha256"], args.dir)
                if ret is False and os.path.exists(filepath):
                    os.remove(filepath)
        print("Download complete.")
    session.close()


"""
目前考虑到一些问题：
1、由于下载量有限，所以在query后，下载前应该把已经存在在数据库中的APK删除，不能重复下载
2、考虑到IO压力，最大循环和单个文件夹最大文件数目应该控制
3、考虑到有些字段，例如aosp证书会造成爆炸式搜集，这个应该得到处理
4、目前没有考虑，已经有数据库情况，只有Koodous一个信息来源
5、很多的特征其实都是重复的，不可能如此冗余的进行所有的查询，得清楚重复值
"""


def Core_engine(input, output, config, limit=50, flodermax=1000):
    """
    input初始APK文件夹
    output下载迭代文件夹，output/1,output/2依次展开
    限制最多50轮相关性迭代
    单个文件夹中最多包含1000个APK
    """
    counter = 0
    inputdir = input
    for counter in range(0, 50):
        outputdir = output+'/'+str(counter)
        beginid, endid = Analyzer_engine(inputdir, flodermax, config)
        Cluster_engine(outputdir, beginid, endid, config)
        "上一轮下载的apk即为下一轮的输入"
        inputdir = outputdir


def main():
    parser = argparse.ArgumentParser(description='clustering APP')
    parser.add_argument("-f",
                        "--folder",
                        action="store",
                        help="Folder to read APKs from.",
                        required=True)
    parser.add_argument("-s",
                        "--store",
                        action="store",
                        help="Folder to store teh download APK.",
                        required=True)
    args = parser.parse_args()
    config = json.load(open('config.json', 'r'))
    Core_engine(args.folder, args.store, config)


if __name__ == "__main__":
    main()
