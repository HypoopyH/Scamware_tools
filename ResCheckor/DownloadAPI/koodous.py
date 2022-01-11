import requests
from urllib.parse import quote
import json
import certifi
from urllib.request import urlretrieve
import argparse
import socket
import os
from urllib.error import *

BASE_URL = 'http://api.koodous.com'
REQUESTS_CA_BUNDLE = certifi.where()
TOKEN = "2427f68e297ad06e9316ff2254a64768210bc527"
socket.setdefaulttimeout(60)

def search(search_term, limit=None):
    ret = list()
    next_page = '%s/apks?search=%s' % (BASE_URL, quote(search_term))

    if limit is None:
        limit = float('Inf')

    while next_page:
        response = requests.get(url=next_page, verify=REQUESTS_CA_BUNDLE)
        next_page = response.json().get('next', None)
        results = response.json().get('results', [])
        ret.extend(results)

        if len(ret) > limit:
            break

    return ret

def download_single(sha256, download_dir):
    print("Downloading", sha256, "...", end=" ", flush=True)
    url = "%s/apks/%s/download" % (BASE_URL, sha256)
    try:
        r = requests.get(url, headers={'Authorization': 'Token %s' % TOKEN},timeout = (2,4))
    except:
        print("链接超时")
        return False
    if r.status_code == 200:
        download_url = r.json().get("download_url", None)
        if download_url is not None:
            try: 
                urlretrieve(download_url, os.path.join(download_dir, "%s.apk" % sha256))
                print("complete.", flush=True)
                return True
            except HTTPError as e:
                print("failed, error:", e, flush=True)
            except socket.timeout:
                print("time out")
        else:
            print("No url found, response is: %s", r.json(), flush=True)
    else:
        print("Request failed (code %d), response: " %(r.status_code), flush=True)
    return False


def main():
    parser = argparse.ArgumentParser(description='Perform request with Koodous.')
    parser.add_argument('-o', '--output',
                       action='store',
                       help='The path to save search result. (Default: stdout)')
    parser.add_argument('-i', '--input',
                       action='store',
                       help='The path search result.')
    parser.add_argument('-s', '--search',
                       action='store',
                       help='The search term.')
    parser.add_argument('-d', '--dir',
                       action='store',
                       default="KoodousSample/",
                       help='Where to save the downloaded APKs. (Default: KoodousSample/)')
    parser.add_argument('-l', '--limit',
                       action='store',
                       default=None,
                       help='Search result limit. (Default: No limit)')

    args = parser.parse_args()

    if args.input is not None and args.search is not None:
        print("Parameter input and search is exclusive.")
        return

    if args.input is not None:
        if not os.path.exists(args.dir):
            os.makedirs(args.dir)

        data = json.load(open(args.input))
        apks = data.get("results", [])
        for apk in apks:
            sha256 = apk["sha256"]
            filepath = os.path.join(args.dir, "%s.apk" % sha256)
            if os.path.exists(filepath):
                print("SHA256 %s exists." % sha256)
            else:
                ret = download_single(apk["sha256"], args.dir)
                if ret is False and os.path.exists(filepath):
                    os.remove(filepath)
        print("Download complete.")
        return
    
    if args.search is not None:
        apks = search(search_term=args.search, limit=int(args.limit))
        result = {
            "term": args.search,
            "results": apks
        }
        print("Search '%s' returned %d results." % (args.search, len(apks)))

    if args.output is None:
        print(json.dumps(result, indent=2))
    else:
        json.dump(result, open(args.output, "w"), indent=2)


if __name__ == "__main__":
    main()
