#!/usr/bin/env python3
"""
Created on Wed Dec 25 2020

@author: beizishaozi
"""
import logging
import sys
import shutil
from apkutils import APK
import re

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import os
from libs.modules.BaseModule import BaseModule

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)



def extract_startpage(mainactivityfile):
    launch_path = []
    fp = open(mainactivityfile)
    data = fp.read()
    m = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                   data)  #
    if m:
        for tmp in m:
            if tmp not in launch_path:
                launch_path.append(tmp)
    k = re.findall('file:///android_asset/(?:[-\w.]|(?:%[\da-fA-F]{2}))+', data)
    if k:
        for tmp in k:
            if tmp not in launch_path:
                launch_path.append(tmp)
    fp.close()
    return " ".join(launch_path)


class AppInventor(BaseModule):
    def doSigCheck(self):
        if self.host_os == "android":
            # com.google.appinventor.components.runtime.multidex.MultiDexApplication is application name
            apk = APK(self.detect_file)  # reference "https://github.com/TheKingOfDuck/ApkAnalyser"
            if apk.get_manifest() \
                    and 'application' in apk.get_manifest() \
                    and '@android:name' in apk.get_manifest()['application'] \
                    and apk.get_manifest()['application'][
                '@android:name'] == "com.google.appinventor.components.runtime.multidex.MultiDexApplication":
                return True
        elif self.host_os == "ios":
            log.error("not support yet.")
            return False
        return False

    def doExtract(self, working_folder):
        extract_folder = self._format_working_folder(working_folder)

        if os.access(extract_folder, os.R_OK):
            shutil.rmtree(extract_folder)
        os.makedirs(extract_folder, exist_ok=True)
        tmp_folder = os.path.join(os.getcwd(), extract_folder, "tmp")
        os.makedirs(tmp_folder, exist_ok=True)
        self._apktool(tmp_folder)

        launch_path = ""
        # apk = APK(self.detect_file)
        # package = str(apk.get_manifest()['@package'])
        # mainactivity = str(apk.get_manifest()['application']['activity'][
        #                        '@android:name'])  # app only contain one activity, name is ".xxx"
        mainactivity = self._get_main_activity()
        mainactivity_last_dir = "/".join(mainactivity.split(".")[:-1])
        for dirpath, dirnames, ifilenames in os.walk(tmp_folder):
            if dirpath.find("assets") != -1:  # store web resource
                for fs in ifilenames:
                    f = os.path.join(dirpath, fs)
                    matchObj = re.match(r'(.*)assets/(.*)', f, re.S)
                    newRP = matchObj.group(2)

                    tf = os.path.join(extract_folder, newRP)
                    if not os.access(os.path.dirname(tf), os.R_OK):
                        os.makedirs(os.path.dirname(tf))
                    with open(tf, "wb") as fwh:  # output the plain
                        # ugly coding
                        fp = open(os.path.join(dirpath, fs), "rb")
                        c = fp.read()
                        fp.close()
                        fwh.write(c)
                    fwh.close()
            # extract the launch path
            elif dirpath.find(mainactivity_last_dir) != -1:
                for fs in ifilenames:
                    if fs.split(".")[0] != mainactivity.split(".")[-1]:
                        continue
                    launch_path = extract_startpage(os.path.join(dirpath, fs))

            # elif dirpath.find(package.replace(".", "/")) != -1: 
            #     for fs in ifilenames:
            #         if fs.split(".")[0] != mainactivity[1:]:  
            #             continue
            #         launch_path = extract_startpage(os.path.join(dirpath, fs))

        self._dump_info(extract_folder, launch_path)
        # clean env
        shutil.rmtree(tmp_folder)
        return extract_folder, launch_path


def main():
    f = "./test_case/AppInventor/test.apk"  
    appinventor = AppInventor(f, "android")
    if appinventor.doSigCheck():
        logging.info("App Inventor signature Match")

        extract_folder, launch_path = appinventor.doExtract("working_folder")
        log.info("{} is extracted to {}, the start page is {}".format(f, extract_folder, launch_path))

    return


if __name__ == "__main__":
    sys.exit(main())
