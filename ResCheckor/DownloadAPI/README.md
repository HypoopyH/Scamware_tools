## Koodous API

How to use:

### Search 

```shell
# Fake Zhonghang APP demo:
python koodous.py -s "com.hw.app1*" -o KoodousSearchResult/frauddemo.json
# Luoliao demo:
python koodous.py -s "developer:1517898990@qq.com" -o KoodousSearchResult/luoliao.json
```

### Download

```shell
# Download Luoliao related APKs based on previous search result.
# Save in KoodousSample directory.
python koodous.py -i KoodousSearchResult/luoliao.json 
```