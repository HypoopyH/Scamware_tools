#!/usr/bin/env python3
"""
Created on Tues JAN 08 2021

@author: beizishaozi
"""

import logging
import sys
import shutil
import re
from apkutils import APK
import zipfile

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import os
from libs.modules.BaseModule import BaseModule

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


class Shoutem(BaseModule):
    blacklist = ["http://api.shoutem.com"]  #链接黑名单
    def extract_startpage(self, filepath):
        fp = open(filepath, "r")
        f = fp.read()
        matchObj = re.findall(',\{type:"shoutem.core.shortcuts",id:"[a-z0-9]{24}",attributes:\{(.+)\},relationships:', f, re.S)

        launch_url=[]
        screens = ("type:\"shoutem.core.shortcuts\",id:\"111122223333444455556666\",attributes:{" + ((str)(matchObj[0]))).split(",relationships:")
        for screen in screens:
            #print(screen)
            idex = screen.find("type:\"shoutem.core.shortcuts\"")
            if idex >= 0:
                screen2 = screen[idex:]
                print(screen2)
                idex = screen2.find(",screens:[") 
                if idex < 0:
                    continue
                screen3 = screen2[idex:]
                idex = screen3.find("],settings")
                if idex < 0:
                    continue
                screen4 = screen3[idex:]
                matchurl = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',screen4)  #https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+
                for url in matchurl:
                    if url in launch_url or url in self.blacklist:
                        continue
                    launch_url.append(url)
        return " ".join(launch_url)

    def doSigCheck(self):
        if self.host_os == "android":
            flag = 0
            flag1 = 0
            flag2 = 0
            apk = APK(self.detect_file)  #reference "https://github.com/TheKingOfDuck/ApkAnalyser"
            #
            appliname = (str)(apk.get_manifest()['@package'])
            print(appliname)
            if appliname.startswith("hr.apps.n"):
                flag = 1
            print(flag)
            zf = zipfile.ZipFile(self.detect_file, 'r')
            for f in zf.namelist():
                if f.startswith("assets/fonts"):
                    flag1 = 1
                elif f == "assets/CodePushHash":
                    flag2 = flag2 + 1
                elif f == "assets/index.android.bundle":
                    flag2 = flag2 + 1
                elif f == "assets/ula.kml":
                    flag2 = flag2 + 1
            if flag + flag1 + flag2 == 5:
                return True
        elif self.host_os == "ios":
            log.error("not support yet.")
            return False
        return False

    def doExtract(self, working_folder):
        extract_folder = self._format_working_folder(working_folder)
        if os.access(extract_folder, os.R_OK):
            shutil.rmtree(extract_folder)
        os.makedirs(extract_folder, exist_ok = True)
        tmp_folder = os.path.join(os.getcwd(), extract_folder, "tmp")
        os.makedirs(tmp_folder, exist_ok = True)
        z = zipfile.ZipFile(self.detect_file, 'r')
        z.extractall(tmp_folder)
        z.close()

        launch_path = self.extract_startpage(os.path.join(tmp_folder, "assets/index.android.bundle"))

        self._dump_info(extract_folder, launch_path)
        # clean env
        shutil.rmtree(tmp_folder)
        return extract_folder, launch_path


def main():
    f = "./test_case/Shoutem/shoutemapp8.apk"    
    shoutem = Shoutem(f, "android")
    if shoutem.doSigCheck():
        logging.info("Shoutem signature Match")

        extract_folder, launch_path = shoutem.doExtract("working_folder")
        log.info("{} is extracted to {}, the start page is {}".format(f, extract_folder, launch_path))

    return

if __name__ == "__main__":
    sys.exit(main())
