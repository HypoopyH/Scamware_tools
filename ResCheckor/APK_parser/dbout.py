from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


"""StaticInfo表
    create table StaticInfo(
        id int(10) unsigned not null auto_increment,
        appname varchar(100) not null comment 'APP名字',
        md5 char(32) not null comment 'APPmd5',
        packagename varchar(100) not null comment 'APP包名',
        android_version varchar(100) comment '目标安卓版本',
        min_sdk char(10) comment '最低sdk版本',
        max_sdk char(10) comment '最高sdk版本',
        size int(10) comment 'APK字节数',
        cert_md5 char(32) not null comment 'certmd5',
        cert_sha1 char(40) not null comment 'certsha1',
        cert_sha256 char(64) not null comment 'certsha256',
        country varchar(50) comment '国家',
        tate varchar(50) comment '省份',
        organization varchar(50) comment '组织名',
        organizationalUnit varchar(50) comment '单位名',
        commonName varchar(200) comment '通用名',
        primary key (id)
        )engine=InnoDB auto_increment=1 default charset=utf8;
"""

"""URL表
    create table URL(
        id int(10) unsigned not null auto_increment,
        md5 char(32) not null comment 'APPmd5',
        HTTPs varchar(500) comment 'HTTP列表',
        IPs varchar(500) comment 'IP列表',
        alive_url_num int(10) comment '可达url数目',
        alive_url varchar(500) comment '可达url',
        url_feature
        
        primary key (id)
        )engine=InnoDB auto_increment=1 default charset=utf8;
"""

"""Resource表
    create table Resource(
        id int(10) unsigned not null auto_increment,
        icon_path varchar(100) comment 'APP图标地址',
        icon_md5 char(32) comment '图标md5',
        music_path varchar(100) comment 'APP内置音乐地址',
        music_md5 char(32) comment '音乐md5',
        primary key (id)
        )engine=InnoDB auto_increment=1 default charset=utf8;
"""
"""Jsondata表
    create table Jsondata(
        id int(10) unsigned not null auto_increment,
        feature varchar(2000) comment 'APP特征行为',
        permission varchar(2000) comment 'APP所包含的特权',
        ips varchar(2000) comment 'APP内置IP',
        domain varchar(2000) comment 'APP内置域名',
        primary key (id)
        )engine=InnoDB auto_increment=1 default charset=utf8;
    """
Base = declarative_base()


class APKfile(Base):
    __tablename__ = 'APKfile'
    id = Column(Integer, primary_key=True)
    filepath = Column(String(200))
    md5 = Column(String(32))


class StaticInfo(Base):
    __tablename__ = 'StaticInfo'
    id = Column(Integer, primary_key=True)
    appname = Column(String(20), nullable=False)
    md5 = Column(String(32),nullable=False)
    packagename = Column(String(40), nullable=False)
    android_version = Column(String(10))
    min_sdk = Column(String(10))
    max_sdk = Column(String(10))
    apksize = Column(Integer)
    cert_md5 = Column(String(32), nullable=False)
    cert_sha1 = Column(String(40), nullable=False)
    cert_sha256 = Column(String(64), nullable=False)
    country = Column(String(20))
    tate = Column(String(20))
    organization = Column(String(50))
    organizationalUnit = Column(String(50))
    commonName = Column(String(50))


def create_session(dbtype, username, password, ip, dbname):
    connect_key = '%s+py%s://%s:%s@%s/%s' % (dbtype,
                                             dbtype, username, password, ip, dbname)
    engine = create_engine(connect_key)
    DBsession = sessionmaker(bind=engine)
    session = DBsession()

    return session


def add_APKfile(session, data):
    """
    传入的是all_data，多个字典集合
    """
    add_list = []
    for (i, v) in data.items():
        APKfile_sample = APKfile(filepath=v['filepath'], md5=v['md5'])
        add_list.append(APKfile_sample)
    session.add_all(add_list)
    session.commit()


def add_StaticInfo(session, data):
    """
    传入的是all_data，多个字典集合
    """
    add_list = []
    for (i, v) in data.items():
        StaticInfo_sample = StaticInfo(
            appname=v['appname'], md5=v['md5'],packagename=v['packagename'], android_version=v['android_version'],
            min_sdk=v['min_sdk'], max_sdk=v['max_sdk'], apksize=v['apksize'],
            cert_md5=v['cert_md5'], cert_sha1=v['cert_sha1'], cert_sha256=v['cert_sha256'],
            country=v['country'], tate=v['tate'],
            organization=v['organization'], organizationalUnit=v['organizationalUnit'],
            commonName=v['commonName']
        )
        add_list.append(StaticInfo_sample)
    session.add_all(add_list)
    session.commit()

def add_URL(session,data):
    """
    NOT finish yet
    Need to design a new database Table.
    """
    return


def delete_table(session, Table, filter):
    session.query(Table).filter_by(filter).delete()
    session.commit()


if __name__ == "__main__":
    session = create_session('mysql', 'yourusername', 'yourpasswd', 'localhost', 'OldMoney_test')

    data = {}
    data["1"] = {}
    data['1']['APKpath'] = "test"
    data['1']['md5'] = "1"
    data["2"] = {}
    data["2"]["APKpath"] = "test2"
    data["2"]["md5"] = "2"

    #add_APKfile(session, data)
    session.query(APKfile).delete()
    session.query(StaticInfo).delete()
    session.commit()
    session.close()
