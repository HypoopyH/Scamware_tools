# 1. App Information Checker

Features:
1. Check Native/hybrid/web framework
2. Check the developer information and permission in Mainfest
3. Check sensitive URL/words/libs in apk

# 2. Get started

## 2.1. Prerequisites
```
$ git clone --recurse-submodules https://github.com/FreshHillyer/ResChecker.git
$ cd ResChecker
$ virtualenv -p python3 venv
$ source venv/bin/activate
$ pip3 install -r requirements.txt
```

## 2.2. ways to check information
The APK_parser folder contains the functionality 
```
$ cd APK_parser
$ python basic_parser -f target_folder #check basic information in Mainfest
$ python h5_parser -f target_folder #check sensitive url information

...
```
