#!/usr/bin/env python3
"""
Created on Wed Dec 25 2020

@author: beizishaozi
"""

import logging
import sys
import shutil
import re

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import os
from libs.modules.BaseModule import BaseModule

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


class AppsGeyser(BaseModule):
    def doSigCheck(self):
        if self.host_os == "android":
            return self._find_main_activity('com.appsgeyser.multiTabApp.MainNavigationActivity')
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
        self._apktool(tmp_folder)

        launch_path = ""
        for dirpath, dirnames, ifilenames in os.walk(tmp_folder):
            
            if dirpath.find("audience_network") != -1:
                continue
            if dirpath.find("assets") != -1:   # store web resource
                for fs in ifilenames:
                
                    if fs == "audience_network.dex" or fs == "splash_screen.png" or fs == "user_custom_script.js":
                        continue
                    f = os.path.join(dirpath, fs)
                    matchObj = re.match(r'(.*)assets/(.*)', f, re.S)
                    newRP = matchObj.group(2)

                    tf = os.path.join(extract_folder, newRP)
                    if not os.access(os.path.dirname(tf), os.R_OK):
                        os.makedirs(os.path.dirname(tf))
                    with open(tf, "wb") as fwh:  #output the plain
                        # ugly coding
                        fp = open(os.path.join(dirpath, fs), "rb")
                        c = fp.read()
                        fp.close()
                        fwh.write(c)
                    fwh.close()
            elif dirpath.endswith("res/raw") != -1:
                for fs in ifilenames:
                    if fs != "configuration.xml":  
                        continue
                    t = ET.ElementTree(file=os.path.join(dirpath, fs))
                    for elem in t.iter(tag='fullScreenMode'):
                        for subelem in elem.iter(tag='content'):
                            for linkelem in subelem.iter(tag='link'):
                                launch_path = linkelem.text

        self._dump_info(extract_folder, launch_path)
        # clean env
        shutil.rmtree(tmp_folder)
        return extract_folder, launch_path


def main():
    f = "./test_case/AppsGeyser/examplehtmlzip.apk"    
    appsgeyser = AppsGeyser(f, "android")
    if appsgeyser.doSigCheck():
        logging.info("Andromo signature Match")

        extract_folder, launch_path = appsgeyser.doExtract("working_folder")
        log.info("{} is extracted to {}, the start page is {}".format(f, extract_folder, launch_path))

    return

if __name__ == "__main__":
    sys.exit(main())
