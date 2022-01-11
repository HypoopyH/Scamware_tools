## Analyzer 

Analyzer for local APKs.

Currently support:

* APICloud: extract APPID.

### 设计文档

所有基本类的实现在`analyzer_base.py`中。设计思路如下：

* 核心组件Runner：程序的总入口
* Input：负责从各个来源读取输入，返回APK文件/字节流
* Analyzer：负责根据特征分析传进来的APK，并提取重要信息
  * 设计时考虑了用Analyzer分析基本特征并入库的需求
* Output：负责将Analyzer返回的所有数据进行输出（JSON，数据库等）

文档：

* Runner初始化参数：
  * limit：限制分析的APK总个数（默认不限制）。
  * save_period：保存输出的间隔（默认到最后再统一输出）。
* Input：
  * 实现__iter__函数，初始化迭代器参数，必须返回self。
  * 实现__next__函数，返回下一个文件。返回str会作为路径读取，返回bytes将被当成文件内容。可以返回额外的信息（metadata），当parse出错的时候用于debug。
* Analyzer：
  * 实现name属性，设置在输出数据中这个Analyzer的子dict。
  * 实现analyze方法，传入APK并返回数据（可以不返回任何数据）。
* Output：
  * 实现save_result方法，保存传入的dict。

### 环境需求

* virtualenv
  * version 15.1.0
  * python version 3.6
  * androguard
  * hashlib

* command line
```bash
  pip install virtualenv
  cd [project]
  virtualenv [project_env]
  virtualenv -p [path of python3.6] [project_env]
  source [project_env]/bin/activate
  pip install -U androguard[magic,GUI],hashlib
```