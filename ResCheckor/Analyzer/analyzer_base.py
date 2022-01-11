from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from functools import lru_cache
from hashlib import md5, sha1, sha256
from fnmatch import fnmatch
import re
import os
import sys
import argparse
import json
import chardet
import magic

INT_MAX = sys.maxsize

"""
    This sketch may help understand the hierarchical structure of AZAPK:
    
    -------------------------------------------------------------------------
    super class: Androguard APK
    |
    |
    AZAPK
       |----AZFileList
               |------AZFile
               |------AZFile
               |....
               |------AZFile
    -------------------------------------------------------------------------
"""

class AZFile:
    """
    AZFile represent a single file of APK decompiler
    """
    def __init__(self, apk: APK, name: str):
        self.name = name
        self.apk = apk
        self._content = None

    @property
    @lru_cache(None)
    def md5(self):
        return md5(self.content).hexdigest()

    @property
    @lru_cache(None)
    def sha1(self):
        return sha1(self.content).hexdigest()

    @property
    def content(self):
        if self._content is None:
            self._content = self.apk.get_file(self.name)
        return self._content
        
    def text(self, encoding='utf-8'):
        try:
            return self.content.decode(encoding=encoding)
        except:
            try:
                return self.content.decode(encoding='gbk')
            except:
                return ""

    def satisfy(self, func):
        return func(self)


class AZFileList:
    """
    AZFileList represent a subset of AZFile, used by a dict __getitem__
    """
    def __init__(self, apk: APK, filelist=None):
        self.apk = apk
        if filelist == None:
            filelist = apk.get_files()
        self._files = dict([(i, AZFile(apk, i)) for i in filelist])

    def __getitem__(self, pat):
        """
        __getitem__: the apk.files[pat] operator.
        `pat` can be an glob pattern.
        Returns an AZFile or AZFileList.
        
        Example:
        >>> apk.files["*libcocos2dlua.so"]
        """
        f = self._files.get(pat, None)
        if f is not None:
            return f

        matches = [i for i, f in self._files.items() if fnmatch(i, pat)]
        return AZFileList(self.apk, matches)

    def __repr__(self):
        return f"<FileList package={self.apk.get_package()}, len={len(self._files)}>"

    def __iter__(self):
        return iter(self._files.values())
           
    @property
    def names(self):
        """
        Returns all files in this FileList.
        """
        return list(self._files.keys())

    @property
    def empty(self):
        """
        Returns True if this list has no files.
        """
        return len(self._files) == 0

    def __len__(self):
        """
        Returns the length of this FileList.
        """
        return len(self._files)

    def match(self, regex):
        """
        Returns the list of files whose name matches a given regex.
        """
        if type(regex) == str:
            regex = re.compile(regex)
        matches = [n for n, f in self._files.items() if regex.match(n)]
        return AZFileList(self.apk, matches)

    def has_md5(self, md5_hex):
        """
        Returns true if any file in this list has a matching MD5.
        """
        for f in self._files.values():
            if f.md5 == md5_hex:
                return True
        return False

    def has_sha1(self, sha1_hex):
        """
        Returns True if any file in this list has a matching SHA-1.
        """
        for f in self._files.values():
            if f.sha1 == sha1_hex:
                return True
        return False

    def filter(self, func):
        """
        Return a list of file that satisfy func (i.e. func(file) return true.)
        Parameter for func is AZFile (i.e. can obtain file content).
        """
        return AZFileList(
            self.apk, [n for n, f in self._files.items() if f.satisfy(func)])

    def any(self, func):
        """
        Returns True if any file satisfies func.
        Parameter for func is AZFile (i.e. can obtain file content).
        """
        for f in self._files.values():
            if f.satisfy(func):
                return True
        return False

    def all(self, func):
        """
        Returns True if ALL file satisfies func.
        Parameter for func is AZFile (i.e. can obtain file content).
        """
        for f in self._files.values():
            if not f.satisfy(func):
                return False
        return True

    def text_files(self):
        """
        Return a list of text files.
        """
        mime = lambda f: magic.from_buffer(f.content, mime=True)
        return self.filter(lambda f: mime(f).startswith("text"))

    def find_text(self, regex):
        """
        Find a regex in all text files.
        """
        result = []
        for f in self.text_files():
            enc = chardet.detect(f.content)["encoding"]
            text = f.text(enc)
            r = re.compile(regex)
            result.extend(r.findall(text))
        return result
    
    def find_text_byone(self, regex):
        """
        Find only one regex in all text files.
        """
        result = []
        for f in self.text_files():
            enc = chardet.detect(f.content)["encoding"]
            text = f.text(enc)
            r = re.compile(regex)
            res = r.findall(text)
            if(res!=[]):
                result.extend(res[0])
            else:
                result.extend(res)
        return result

    @property
    def md5(self):
        """
        Returns a dict of files' MD5 (i.e. file_name -> md5_sum)
        """
        return dict([(n, f.md5) for n, f in self._files.items()])

    @property
    def sha1(self):
        """
        Returns a dict of files' SHA-1 (i.e. file_name -> sha1_sum)
        """
        return dict([(n, f.sha1) for n, f in self._files.items()])


class AZDEX:
    def __init__(self, apk: APK):
        """
        A wrapper for all DEXes in the APK.
        """
        self.dex = [DalvikVMFormat(buf) for buf in apk.get_all_dex()]
        self._strings = None
        self._classes = None

    @property
    def strings(self):
        """
        Returns a list of all strings in all DEXes.
        """
        if self._strings is None:
            self._strings = []
            for dex in self.dex:
                self._strings.extend(dex.get_strings())
        return self._strings

    @property
    def classes(self):
        if self._classes is None:
            self._classes = []
            for dex in self.dex:
                self._classes.extend(dex.get_classes_names())
        return self._classes

    def strings_match(self, regex: str):
        """
        Returns all strings that satisfy a given regex string.
        """
        r = re.compile(regex)
        return list(filter(r.match, self.strings))

    def strings_find(self, regex: str):
        """
        Search for a regex in all strings.
        """
        def flatten(l): 
            return [item for sublist in l for item in sublist]

        r = re.compile(regex)
        return flatten([i for i in [r.findall(e) for e in self.strings] if i])
    


class AZAPK(APK):
    """
    AZAPK is the subclass of the Androguard class APK
    It contain a AZFileList for better suit for Batch processing
    """
    def __init__(self, filename, raw=False):
        super().__init__(filename, raw)
        self.filename = filename
        self.__files = None
        self._dex = None
    
    def raw(self):
        """
        Returns raw data of the entire APK.
        """
        return self.get_raw()
    @property
    def apksize(self):
        """
        Returns the size of the entire APK.
        """
        return int(len(self.raw()))
    @property
    def md5(self):
        """
        Returns the MD5 checksum of the entire APK.
        """
        return md5(self.raw()).hexdigest()
    @property 
    def sha1(self):
        """
        Returns the SHA-1 checksum of the entire APK.
        """
        return sha1(self.raw()).hexdigest()
    @property    
    def sha256(self):
        """
        Returns the SHA-256 checksum of the entire APK.
        """
        return sha256(self.raw()).hexdigest() 
    
    @property
    def files(self):
        """
        .files is a main modification that returns a list of files 
        for better file handling with AndroGuard.
        See AZFileList for details.
        """
        if self.__files == None:
            self.__files = AZFileList(self)
        return self.__files

    @property
    def dex(self):
        if self._dex is None:
            self._dex = AZDEX(self)
        return self._dex


class AnalyzerBase:
    """
    AnalyzerBase is the base class for every Analyzer.
    Every Analyzer must implement a method called `analyze` to receive APK to analyze.
    """
    @property
    def name(self):
        """
        Analyzer can optionally define a name to provide key to output data.
        Default implementation is to use class name.
        """
        return type(self).__name__

    def analyze(self, apk: AZAPK):
        """
        The main entry for Analyzer to receive APK.
        """
        raise NotImplementedError(
            "Subclass of AnalyzeBase should implement analyze method.")


class OutputBase:
    """
    OutputBase is the base class for every Output.
    Every Output must implement a method called `save_result` to receive aggregated output for analyzer.
    """
    def save_result(self, data: dict):
        raise NotImplementedError(
            "Subclass of OutputBase should implement save_result method.")


class StdOutput(OutputBase):
    """
    Simplest implementation: directly print to output.
    """
    def save_result(self, data: dict):
        print(data)


class JsonOutput(OutputBase):
    """
    An example Output with custom __init__ and parameter.
    """
    def __init__(self, f: str):
        self.fpath = f

    def save_result(self, data: dict):
        json.dump(data, open(self.fpath, "w"), indent=2)


class InputBase:
    """
    InputBase class.
    InputBase is an iterator-based class, you first overwrite __iter__ for some context data (like current index of iterator).
    Then, __next__ is called when Runner requests APK data.
    You can either return str as path to the APK file, or bytes data containing real APK information.
    You can also return metadata for this input, which will be printed when parsing the APK fails.
    """
    def __iter__(self):
        """
        Default implementation is to return self.
        """
        return self

    def __next__(self):
        raise NotImplementedError(
            "Subclass of InputBase should implement __next__ method.")


class DirInput(InputBase):
    """
    An example of InputBase implementation to list a directory for apks.
    Can also serve as a base class for Input that filters a directory. 
    """
    def __init__(self, folder: str):
        self.folder = folder
        self.iter = self.get_apk_iter()

    def get_apk_iter(self):
        """
        The main entry is get_apk_iter that returns an iterator of APK file paths.
        """
        return iter(
            os.path.join(self.folder, a) for a in os.listdir(self.folder)
            if a.endswith(".apk"))

    def __next__(self):
        file_name = next(self.iter)
        return file_name, {"file_name": file_name}

"""
class VirusTotalInput(InputBase):
    def __init__(self, f: str):
        if f.endswith(".7z"):
            self.fpath = f
            self.fp = open(f, "rb")
            self.load_archive(VIRUSTOTAL_PASSWORDS)

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        next_name = self.names[self.index]
        next_file = self.archive.getmember(next_name).read()
        self.index += 1
        return next_file, True

    def load_archive(self, password_list):
        for password in password_list:
            self.fp.seek(0)
            archive = py7zlib.Archive7z(self.fp, password)
            names = archive.getnames()
            f = archive.getmember(next(n for n in names
                                       if n.endswith(".json")))
            try:
                f.read()
                self.archive = archive
                self.names = [a for a in names if not a.endswith(".json")]
                print("Detected password for %s is %s" %
                      (self.fpath, password))
                return
            except:
                continue

        self.archive = None
        self.names = []
        print("Warn: no password found for %s", self.fpath)

"""

class Runner:
    def __init__(self, inputs, limit=None, save_period=None):
        """
        Constructor for Runner.
        inputs: list of InputBase classes to read APK files from. See InputBase class above.
        limit: limit the total number of APKs analyzed. None means no limit.
        save_period: periodically save output data to each OutputBase class. None means only output when all analysis finishes.
        """
        self.inputs = inputs
        self.outputs = []
        self.analyzer_list = []
        self.limit = limit if limit is not None else INT_MAX
        self.save_period = save_period if save_period is not None else INT_MAX

    def add_input(self, inp: InputBase):
        """
        Add an input class.
        inp: an InputBase class.
        """
        self.inputs.append(inp)

    def add_output(self, output):
        """
        Add an output class.
        output: an OutputBase class.
        """
        self.outputs.append(output)

    def add_analyzer(self, analyzer_class):
        """
        Add an analyzer class.
        inp: an AnalyzerBase class.
        """
        self.analyzer_list.append(analyzer_class())

    def _save_result(self, data: dict):
        for output in self.outputs:
            output.save_result(data)

    def run(self):
        """
        Start the analysis process.
        """
        all_data = {}
        counter = 0
        done = False

        for inp in self.inputs:
            for (f, metadata) in inp:
                is_raw = True if type(f) == bytes else False
                try:
                    apk_obj = AZAPK(f, is_raw)
                except Exception as e:
                    print("Parse apk failed, metadata: %s, error: %s" %
                          (metadata, e))
                    continue
                
                counter += 1
                print("Analyzing APK: %s" % metadata)
                for analyzer in self.analyzer_list:
                    pkgname = apk_obj.get_package()
                    data = analyzer.analyze(apk_obj)

                    if data is not None:
                        if pkgname not in all_data.keys():
                            all_data[pkgname] = {}
                        for k, v in data.items():
                            all_data[pkgname][k] = v

                if counter > self.limit:
                    done = True
                    break

                if counter % self.save_period == 0:
                    self._save_result(all_data)
                    all_data = {}

            if done:
                print("Limit %d reached." % self.limit)
                break

        self._save_result(all_data)


def xxtea_decrypt(b: bytes, key: bytes, skip_prefix=0, pad_key=True):
    import xxtea
    if len(key) < 16 and pad_key:
        key = key.ljust(16, b'\0')
    xxtea.decrypt(b[skip_prefix:], key, False)