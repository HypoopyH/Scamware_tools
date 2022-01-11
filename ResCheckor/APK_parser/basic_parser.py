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
import csv
sys.path.append("..")
from Analyzer.analyzer_base import *



def add_parameters(params, **kwargs):
    "parms producer"
    params.update(kwargs)


def get_sign_basic(APKfile):
    """
    certificate basicinfo,package name ,app name and so on
    """
    try:
        "permission"
        permission = APKfile.get_permissions()
        "package name, app name"
        packge_name = APKfile.get_package()
        app_name = APKfile.get_app_name()
        "Android version,sdk version,min sdk,max sdk"
        android_version = APKfile.get_androidversion_name()
        target_sdk = APKfile.get_effective_target_sdk_version()
        min_sdk = APKfile.get_min_sdk_version()
        max_sdk = APKfile.get_max_sdk_version()
        "certificate public key,signature"
        features = APKfile.get_features()
        public_key = APKfile.get_public_keys_v2()
        certificates = APKfile.get_certificates()
        #show_Certificate(certificates[0])
        savedStdout = sys.stdout  # save std io
        with open('out.txt', 'w') as tem_file:
            sys.stdout = tem_file  # >> file
            show_Certificate(certificates[0])
        sys.stdout = savedStdout  # revover stdio
        content = open('out.txt', 'r').read()
        os.remove('out.txt')
        "SHA1,SHA256,country,city,organization,email,user"
        "certificate md5"
        cert_md5 = ''
        certs = set(APKfile.get_certificates_der_v2(
        ) + [APKfile.get_certificate_der(x) for x in APKfile.get_signature_names()])
        "certs will only contain one item if the certificate is not wrong"
        for cert in certs:
            cert_md5 = hashlib.md5(cert).hexdigest()
            cert_md5 = cert_md5.upper()

        SHA1 = re.findall('SHA1 Fingerprint: (.*?)\n', content)[0]
        SHA256 = re.findall('SHA256 Fingerprint: (.*?)\n', content)[0]
        SHA1 = SHA1.replace(" ", "")
        SHA256 = SHA256.replace(" ", "")
        countryName = re.findall('countryName=\(?(.*?)\)?,', content)
        if(len(countryName) > 0):
            countryName = countryName[0]
        else:
            countryName = None
        tateOrProvinceName = re.findall(
            'tateOrProvinceName=\(?(.*?)\)?,', content)
        if(len(tateOrProvinceName) > 0):
            tateOrProvinceName = tateOrProvinceName[0]
        else:
            tateOrProvinceName = None
        organizationName = re.findall('organizationName=\(?(.*?)\)?,', content)
        if(len(organizationName) > 0):
            organizationName = organizationName[0]
        else:
            organizationName = None
        organizationalUnitName = re.findall(
            'organizationalUnitName=\(?(.*?)\)?,', content)
        if(len(organizationalUnitName) > 0):
            organizationalUnitName = organizationalUnitName[0]
        else:
            organizationalUnitName = None
        commonName = re.findall('commonName=\(?(.*?)\)?\n', content)
        if(len(commonName) > 0):
            commonName = commonName[0]
        else:
            commonName = None
        params = {}
        add_parameters(params, permission=permission, packagename=packge_name, appname=app_name, android_version=android_version,
                       target_sdk=target_sdk, min_sdk=min_sdk, max_sdk=max_sdk, features=features,
                       cert_sha1=SHA1, cert_sha256=SHA256, country=countryName, tate=tateOrProvinceName,
                       organization=organizationName, organizationalUnit=organizationalUnitName, cert_md5=cert_md5,
                       commonName=commonName)
        return params
    except:
        return None


class BasicInfoAnalyzer(AnalyzerBase):
    @property
    def name(self):
        return "basic_info"

    def analyze(self, apk: AZAPK):
        params = get_sign_basic(apk)
        if(params == None):
            return None
        add_parameters(params, filepath=apk.filename,
                       apksize=apk.apksize, md5=apk.md5,sha1=apk.sha1)
        return params

# show basic info


def show_basic(params):
    for key in params.keys():
        if params[key] is None:
            params[key] = "None"

    print("FILE:"+'\n\t size:'+str(params['apksize'])+'\n\t md5'+params['md5'])
    print("Certifacate signature:"+'\n\t certificate MD5: '+params['cert_md5']+'\n\t SHA1: '+params['cert_sha1']
          + '\n\t SHA256: '+params['cert_sha256']+'\n\t countryName: '+params['country'] +
          '\n\t tateOrProvinceName: ' +
          params['tate'] +
          '\n\t organizationName: '+params['organization']
          + '\n\t organizationalUnitName: '+params['organizationalUnit']+'\n\t commonName: '+params['commonName'])
    print("APK infomation:\n\t"+"apk name: "+params['appname']+"\n\tpackage name: "+params['packagename']
          + "\n\tandroid_version: " +
          params['android_version'] + "\n\tmin_sdk: "+params['min_sdk']
          + "\n\tmax_sdk: "+params['max_sdk'])
    print("permission: ")
    for i in params['permission']:
        print("\t"+i)
    print("features: ")
    for i in params['features']:
        print("\t"+i)


class BasicInfoOutput(OutputBase):
    """
    Simplest implementation: directly print to output.
    """

    def save_result(self, data: dict):
        for (i, v) in data.items():
            show_basic(v)


class DBinfoOutput(OutputBase):
    """
    Database output
    """

    def save_result(self, data: dict):
        session = create_session(
            'mysql', 'X', 'X', 'localhost', 'X')
        try:
            add_StaticInfo(session, data)
            add_APKfile(session, data)
            print("finish")
        except:
            print("something wrong")
        session.close()


class CSVInfoOutput(OutputBase):
    """
    CSV output
    """

    def save_result(self, data: dict):
        pwd = os.getcwd()
        csvfile = os.path.join(pwd, "APK_ana3.csv")
        if not os.path.exists(csvfile):
            with open('APK_ana3.csv', 'w', newline='',encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(['filepath', 'apksize','sha1', 'md5', 'packagename', 'appname',
                                 'cert_md5', 'cert_sha1', 'country', 'tate',
                                 'organization', 'organizationalUnit',
                                 'commonName', 'permission_num', 'permission', 'features_num', 'features'])
                row = []
                for (i, v) in data.items():
                    for key in v.keys():
                        if v[key] is None:
                            v[key] = "None"
                    permission = ""
                    features = ""
                    for i in v['permission']:
                        permission = permission + i +';'
                    for i in v['features']:
                        features = features + i +';'

                    row.append([v["filepath"], v['apksize'],v['sha1'], v['md5'], v['packagename'], v['appname'],
                                v['cert_md5'], v['cert_sha1'], v['country'], v['tate'], v['organization'], v['organizationalUnit'],
                                v['commonName'], len(v['permission']), permission, len(v['features']), features])
                writer.writerows(row)
                f.close()
        else:
            Column = []
            with open('APK_ana3.csv', 'r', newline='',encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                Column = [row['md5'] for row in reader]
            row = []
            for (i, v) in data.items():
                if v['md5'] in Column:
                    continue
                for key in v.keys():
                    if v[key] is None:
                        v[key] = "None"
                permission = ""
                features = ""
                for i in v['permission']:
                    permission = permission + i +';'
                for i in v['features']:
                    features = features + i +';'

                row.append([v["filepath"], v['apksize'],v['sha1'], v['md5'], v['packagename'], v['appname'],
                            v['cert_md5'], v['cert_sha1'], v['country'], v['tate'], v['organization'], v['organizationalUnit'],
                            v['commonName'], len(v['permission']), permission, len(v['features']), features])
            with open('APK_ana3.csv', 'a', newline='',encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerows(row)


def main():
    begin_time = time.time()
    parser = argparse.ArgumentParser(
        description='Analyse APKs.')
    parser.add_argument("-f",
                        "--folder",
                        action="store",
                        help="Folder to read APKs from.",
                        required=True)
    args = parser.parse_args()

    runner = Runner([DirInput(args.folder)],save_period=1)
    runner.add_analyzer(BasicInfoAnalyzer)
    # runner.add_output(BasicInfoOutput())
    runner.add_output(CSVInfoOutput())
    runner.run()
    end_time = time.time()
    print("total time: %d" % (end_time-begin_time))


if __name__ == "__main__":
    main()
