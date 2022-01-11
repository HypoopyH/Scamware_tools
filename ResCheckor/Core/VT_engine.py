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

def VT_Cluster_engine(outputdir, inputfile, outputfile, config, usedList):
    """
    核心关联部分，通过数据库寻找关联性
    """
    session = create_session('mysql', config.get("Username"), config.get(
        "Password"), 'localhost', 'OldMoney_test')
    """
    demo版本先只考虑StaticInfo,然后查询属性这里引入了json的方法自定义
    """
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    num = 0
    params = json.load(open(inputfile, 'r'))
    table = config.get("Table_List")
    json_content = {}
    for i, v in params.items():
        for ids, value in v.items():
            for coon in table.values():
                tables = coon['name']
                for item in coon["items"]:
                    if(ids == item):
                        MYSQL = "select id from %s where %s=\"%s\"" % (
                            tables, ids, value)
                        result = session.execute(MYSQL).fetchall()
                        for j in result[:]:
                            if(j['id'] in usedList):
                                result.remove(j)
                            else:
                                usedList.append(j['id'])
                        for j in result:
                            MYSQL = "select * from %s where id=%s" % (
                                tables, j['id'])
                            val = session.execute(MYSQL).fetchall()
                            data = [dict(zip(result.keys(), result))
                                    for result in val]

                            data[0]['father'] = i
                            data[0]['relate_item'] = ids
                            json_content[data[0]['packagename']] = data[0]
                            num += 1

    json.dump(json_content, open(outputfile, "w"), indent=2)
    session.close()
    return num


def VT_Core_engine(input, output, config, limit=50, flodermax=1000):
    """
    input初始APK文件夹
    output下迭代json文件，1.json，2.json
    限制最多50轮相关性迭代
    """
    if not os.path.exists(output):
        os.makedirs(output)
    counter = 0
    inputdir = input
    outputfile = os.path.join(output, 'First.json')
    runner = Runner([DirInput(inputdir)], limit=limit)
    runner.add_analyzer(BasicInfoAnalyzer)
    # runner.add_output(BasicInfoOutput())
    runner.add_output(JsonOutput(outputfile))
    runner.run()

    usedList = []
    inputfile = outputfile
    for counter in range(0, 50):
        newjson = os.path.join(output, str(counter)+'.json')
        num = VT_Cluster_engine(output, inputfile, newjson, config, usedList)
        "迭代相关数不再增加则停止"
        if(num == 0):
            break
        inputfile = newjson
        print("finish %d iteration" % counter)


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
    VT_Core_engine(args.folder, args.store, config)


if __name__ == "__main__":
    main()
