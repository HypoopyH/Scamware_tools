from analyzer_base import *
import xml.etree.ElementTree as ET
from io import BytesIO
import json
import argparse


class BasicInfoAnalyzer(AnalyzerBase):
    @property
    def name(self):
        return "basic_info"

    def analyze(self, apk: AZAPK):
        cert = apk.get_certificates()[0]
        subject_org = cert.native["tbs_certificate"]["subject"]["organization_name"] # 'developer'
        return {
            # may be more basic info
            "developer": subject_org,
            "cert_hash": cert.sha1.hex()
        }


class APICloudAnalyzer(AnalyzerBase):
    @property
    def name(self):
        return "apicloud"

    def analyze(self, apk: AZAPK):
        name = apk.get_package()
        print(name)
        activities = apk.get_activities()
        if 'com.uzmap.pkg.LauncherUI' in activities or 'com.uzmap.pkg.EntranceActivity' in activities:
            # We found an APICloud APK
            print("发现APICloud APK:", name, "名称:", apk.get_app_name(), end="")
            try:
                config_file = apk.get_file("assets/widget/config.xml")
            except:
                print("没有config.xml文件，可能是误判或者包损坏。")
                return

            config = BytesIO(config_file)
            et = ET.parse(config)
            widget = et.getroot()
            print(", APPID:", widget.attrib["id"])
            return {"appid": widget.attrib["id"]}


class DBOut(OutputBase):
    def save_result(self, data: dict):
        for pkgname, v in data.items():
            basic_info = v["basic_info"]
        # put basic_info into database


def main():
    parser = argparse.ArgumentParser(
        description='Analyse APKs.')
    parser.add_argument("-f",
                        "--folder",
                        action="store",
                        help="Folder to read APKs from.",
                        required=True)
    args = parser.parse_args()

    runner = Runner([DirInput(args.folder)], limit=50)
    # VirusTotalInput("/mnt/data/Android-2020-05-06.7z")], 
    # analyzer.add_analyzer(BasicInfoAnalyzer)
    runner.add_analyzer(APICloudAnalyzer)
    runner.add_output(StdOutput())
    runner.add_output(JsonOutput())
    runner.run()


if __name__ == "__main__":
    main()