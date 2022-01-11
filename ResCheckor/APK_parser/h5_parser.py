# -*- coding: utf-8 -*-
"""
Created on Thu Nov 19 19:35:49 2020

@author: hypo
"""

from dbout import *
from androguard.core.bytecodes.apk import show_Certificate
import re
import hashlib
import os
import time
import sys
import xml.etree.ElementTree as ET
from io import BytesIO
sys.path.append("..")

from Analyzer.analyzer_base import *

def add_parameters(params, **kwargs):
    "params producer"
    params.update(kwargs)

class H5Analyzer(AnalyzerBase):

    @property
    def name(self):
        return "h5info"

    def analyze(self, apk:AZAPK):
        params = {}
        style = ''
        appid = ''
        adid = ''
        channel = ''
        name = apk.get_package()
        # print(name)
        activities = apk.get_activities()
        try:
            manifest_file = apk.get_android_manifest_axml().get_xml()
        except:
            print("package broken!")
            return
        manifest = BytesIO(manifest_file)
        et = ET.parse(manifest)
        root = et.getroot()
        for permission in root.iter('permission'):
            if (re.search("YM_APP", permission.get("{http://schemas.android.com/apk/res/android}name"))):
                style = 'yimenapp'

        if 'com.uzmap.pkg.LauncherUI' in activities or 'com.uzmap.pkg.EntranceActivity' in activities:
            # an APICloud APK
            try:
                config_file = apk.get_file("assets/widget/config.xml")
            except:
                print("without config.xml!")
                return

            config = BytesIO(config_file)
            et = ET.parse(config)
            widget = et.getroot()
            appid = widget.attrib["id"]

            add_parameters(params, h5=1, style='APICloud', appid=appid, adid=adid, channel=channel)
            return params
        elif 'io.dcloud.PandoraEntry' in activities or 'io.dcloud.PandoraEntry' in activities:
            # an DCloud APK
            for metadata in root.iter('meta-data'):
                #print(metadata.attrib)
                if (metadata.get("{http://schemas.android.com/apk/res/android}name") == "DCLOUD_STREAMAPP_CHANNEL"):
                    value = metadata.get("{http://schemas.android.com/apk/res/android}value")
                    value_list = value.split('|')
                    appid = value_list[1]
                    adid = value_list[2]
                    channel = value_list[3]

            add_parameters(params, h5=1, style='DCloud', appid=appid, adid=adid, channel=channel)
            return params

        elif 'io.gonative.android.MainActivity' in activities or 'io.gonative.android.SplashActivity' in activities or 'io.gonative.android.SubscriptionsActivity' in activities:
            add_parameters(params, h5=1, style='GoNative', appid=appid, adid=adid, channel=channel)
            return params

        elif 'Website2APK' in apk.dex.strings:
            add_parameters(params, h5=1, style='Website2APK', appid=appid, adid=adid, channel=channel)
            return params

        elif b'This app was created in seconds with appenguin.com' in apk.get_android_resources().get_string_resources(apk.get_package()):
            add_parameters(params, h5=1, style='appenguin', appid=appid, adid=adid, channel=channel)
            return params

        elif style == 'yimenapp':
            add_parameters(params, h5=1, style='yimenapp', appid=appid, adid=adid, channel=channel)
            return params

        else:
            # other h5 skill
            add_parameters(params, h5=0, style='other', appid=appid, adid=adid, channel=channel)
            return params

class BasicInfoOutput(OutputBase):
    def save_result(self, data:dict):
        for (i, v) in data.items():
            print(str(v) + "\n")

class DBinfoOutput(OutputBase):
    """
    Database output
    """

    def save_result(self, data: dict):
        session = create_session(
            'mysql', 'X', 'X', 'localhost', 'X')
        add_APKfile(session, data)
        add_StaticInfo(session,data)
        print("finish")
        session.close()

def main():
    begin_time = time.time()
    parser = argparse.ArgumentParser(
        description='h5 parser.')
    parser.add_argument("-f", "--folder", action="store", help="Folder to read APKs from.", required=True)
    args = parser.parse_args()
    runner = Runner([DirInput(args.folder)], limit=50)
    runner.add_analyzer(H5Analyzer)
    runner.add_output(BasicInfoOutput())
    #runner.add_output(DBinfoOutput())
    runner.run()
    end_time = time.time()
    print("total time: %d"%(end_time-begin_time))

if __name__ == "__main__":
    main()