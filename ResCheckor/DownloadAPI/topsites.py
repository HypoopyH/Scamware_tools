#
# Copyright 2019 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
#------------------------------------------------------------------------
#         Python Code Sample for Alexa Top Sites Service          -
#------------------------------------------------------------------------
#
# This sample will make a request to Alexa Top Sites in
# AWS Marketplace using the API user credentials and API plan key. This
# sample demonstrates how to make a SigV4 signed request and refresh
# crdentials from the Cognito pool.
#

import sys, os, base64, hashlib, hmac
import logging, getopt
import boto3
import getpass
import re
import requests
import math
from datetime import datetime
import time
from configparser import ConfigParser # pip install configparser
from future.standard_library import install_aliases
install_aliases()
from urllib.parse import parse_qs, quote_plus

# ************* REQUEST VALUES *************
host = 'ats.api.alexa.com'
endpoint = 'https://' + host
method = 'GET'
logging.basicConfig()
log = logging.getLogger( "ats" )
content_type = 'application/xml'
local_tz = "America/Los_Angeles"
API_key="Gj9SV8Fut16cR7uCbabnN9Dr6ZxfmljxaBRLs4db"


###############################################################################
# usage                                                                       #
###############################################################################
def usage( ):
    sys.stderr.write ( """
Usage: topsites.py [options]

  Make a signed request to Alexa Top Sites API service

  Options:
     -a, --action            Service Action
     -k, --key               API Key
     -c, --country           2-letter Country Code (ie. US, CN, BR)
     -o, --options           Service Options
     -?, --help       Print this help message and exit.

  Examples:
     TopSites by country: topsites.py -k 98hu7.... --action TopSites --country=US --options "&Count=100&Output=json"
""" )

###############################################################################
# parse_options                                                               #
###############################################################################
def parse_options( argv ):
    """Parse command line options."""

    opts = {}

    urlargs = {}

    try:
        user_opts, user_args = getopt.getopt( \
            argv, \
            'k:a:c:o:?', \
            [ 'key=', 'action=', 'country=', 'options=', 'help=' ] )
    except Exception as e:
        print('Command parse error:', e)
        log.error( "Unable to parse command line" )
        return None

    if ( '-?', '' ) in user_opts or ( '--help', '' ) in user_opts:
        opts['help'] = True
        return opts

    #
    # Convert command line options to dictionary elements
    #
    for opt in user_opts:
        if  opt[0] == '-k' or opt[0] == '--key':
            opts['key'] = opt[1]
        elif opt[0] == '-a' or opt[0] == '--action':
            opts['action'] = opt[1]
        elif opt[0] == '-c' or opt[0] == '--country':
            opts['country'] = opt[1]
        elif opt[0] == '-o' or opt[0] == '--options':
            opts['options'] = opt[1]
        elif opt[0] == '-a' or opt[0] == '--action':
            opts['action'] = opt[1]
        elif opt[0] == '-v' or opt[0] == '--verbose':
            log.verbose()

    if 'key' not in opts or \
       'action' not in opts or \
       'country' not in opts:
        return None

    #
    # Return a dictionary of settings
    #
    success = True
    return opts

###############################################################################
# sortQueryString                                                             #
###############################################################################
def sortQueryString(queryString):
    queryTuples = parse_qs(queryString)
    sortedQueryString = ""
    sep=""
    for key in sorted(queryTuples.keys()):
        sortedQueryString = sortedQueryString + sep + key + "=" + quote_plus(queryTuples[key][0])
        sep="&"
    return sortedQueryString

###############################################################################
# main                                                                        #
###############################################################################
if __name__ == "__main__":

    opts = parse_options( sys.argv[1:] )

    if not opts:
        usage( )
        sys.exit( -1 )

    if 'help' in opts:
        usage( )
        sys.exit( 0 )

    canonical_uri = '/api'

    canonical_querystring = 'Action=' + opts['action']
    canonical_querystring += "&" + 'CountryCode=' + opts['country']
    canonical_querystring += "&" + 'ResponseGroup=Country'


    headers = {'Accept':'application/xml',
               'Content-Type': content_type,
               'x-api-key': opts['key']
              }

    # ************* SEND THE REQUEST *************
    if 'options' in opts:
        num = re.findall("Count=(.*?)&",opts['options'])
        if int(num[0])>100:
            for i in range(0,int(int(num[0])/100)):
                num=100*(i+1)
                opts['options']="&Count="+str(100)+"&Output=json&ResponseGroup=Country&Start="+str(num-100+1)
                url = canonical_querystring +"&" +opts['options']
                tail_url = sortQueryString(url)
                request_url = endpoint + canonical_uri + "?" + tail_url
                #print(request_url)


                #print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
                #print('Request URL = ' + request_url)
                r = requests.get(request_url, headers=headers)

                #print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
                #print('Response code: %d\n' % r.status_code)
                print(r.text)
                sleep(50)
