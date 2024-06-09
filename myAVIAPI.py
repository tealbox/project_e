#-------------------------------------------------------------------------------
# Name:           Pankaj Verma
# Description:    Collect all Security Policies
#-------------------------------------------------------------------------------
import requests, json, re, sys
import requests.packages
from typing import List, Dict
from pprint import pprint
import pickle
import os

# from casUtils import *
from concurrent.futures import ThreadPoolExecutor as tPool
import concurrent.futures

from time import sleep
import threading
from threading import Lock
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

lock = Lock()
filetime = datetime.now().strftime("%b_%d_%H_%M_%S")
requests.packages.urllib3.disable_warnings()

class myAVI:
    # create for the ops of NSX4 tasks
    # required requests
    def __init__(self, avimgr, username = "admin", password = ""):

        self.hostname = avimgr
        self.username = username
        self.password = password

        self.headers = { }
##          'Accept-Encoding': 'gzip',
##          'Content-Type': "application/json",
##          'Accept': 'application/json',
##          'Connection': 'keep-alive'
##        }
        # Define the retry strategy
        retry_strategy = Retry(
            total=4,  # Maximum number of retries
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
        )
        # Create an HTTP adapter with the retry strategy and mount it to session
        adapter = HTTPAdapter(max_retries=retry_strategy)

        self.s = requests.Session()
        self.s.mount('https://', adapter)
        self.s.verify = False

        self.baseUrl = f"https://{self.hostname}/api"
        # self.getallServices()

    def __do(self, method="GET", api="", payload={}):
        url = f"{self.baseUrl}{api}"
        # print(url)
        if method == "GET":
          response = self.s.get(url, headers = self.headers )
          # print(response.json())
          if response.status_code >= 200 and response.status_code <= 299:
            return response.json()
          else:
            return "Not able to GET api, please check for login/ip/credentials!!"

    def login(self):
        api = "/login"
        url = f"https://{self.hostname}{api}"
        payload = {
            'username': self.username,
            'password': self.password
        }
        response = self.s.post(url, headers = self.headers, data=payload )
        if response.status_code >= 200 and response.status_code <= 299:
##            print(response.headers)
            headers = response.headers
            head = headers['Set-Cookie'].split()
            self.headers.setdefault("X-CSRFToken", head[0].split(sep="=")[1])
            self.headers.setdefault("Referer", f"https://{self.hostname}")
            self.headers.setdefault("Cookie", f'{head[0]}{head[9]}{head[19]}')
            self.headers.setdefault("X-Avi-Tenant", "*")
            self.headers.setdefault("X-Avi-Version", "20.1.8")
            self.headers.setdefault("Accept", "application/json")

            #'Cookie': 'avi-sessionid=tzvfqjiry9rrsfwiehqyke3d8ejy1m3j; csrftoken=543IFXoN3JNfGreyaRKhIjZts46v0B0g; sessionid=tzvfqjiry9rrsfwiehqyke3d8ejy1m3j'
            print(self.headers)
##            return response.json()

    def logout(self):
        api = "/logout"
        url = f"https://{self.hostname}{api}"
        payload = {}
        response = self.s.post(url, headers = self.headers, data=payload )
        print(response.headers)
        print(response.status_code)
        if response.status_code >= 200 and response.status_code <= 299:
            print("Logout successfully")
            print(response.headers)

    def getVirtualService(self):
        api = '/virtualservice?fields=enabled,traffic_enabled,type,pool_ref&page_size=100'
        response = self.__do(method="GET", api=api, payload={})
        totalRecords  = response.get('count', 0)
        self.vsDB = []
        if "results" in response:
            self.vsDB.extend(response["results"])
            while 1:
                if "next" in response:
                    next = response["next"]
                    print("Next: ", response.get("next", None))
                    api = response['next'].split(sep='api')[1]
                    response = self.__do(method="GET", api=api)
                    if "results" in response:
                        self.vsDB.extend(response["results"])
##                        print("Length: ", len(self.spDB))
##                        print(response["results"])
                    else:
                        print("Not able to fetch....", response["next"])
                        return self.vsDB
                else:
##                    print("Not able to fetch.... No Cursor")
                    return self.vsDB
            return self.vsDB
        else:
            return None



    def getAPI(self, api):
        sleep(.5)
        return self.__do(method="GET", api=api, payload={})


    def getSPList(self, domainid = "default"):
##        >>> res.keys()
##        dict_keys(['results', 'result_count', 'sort_by', 'sort_ascending', 'cursor'])
##        >>> res1.keys()
##        dict_keys(['results', 'sort_by', 'sort_ascending', 'cursor'])
        domainid = "default"
        cursor = 0
        api = f'/infra/domains/{domainid}/security-policies?page_size=1000'
        print("-*-"*25)
        print("Collecting All security-policies ...")
        response = self.__do(method="GET", api=api)
        self.spDB = []
        if "results" in response:
            # collect only name, id, and path
            # Note::::: Group name are case sensitive
            self.spDB.extend(response["results"])
            totalRecords  = response["result_count"]
            print("Number of records: ", totalRecords)
            while 1:
                if "cursor" in response:
                    cursor = response["cursor"]
                    print("Cursor: ", response["cursor"])
                    api = f'/infra/domains/{domainid}/security-policies?cursor={cursor}&page_size=1000'
                    response = self.__do(method="GET", api=api)
                    if "results" in response:
                        self.spDB.extend(response["results"])
##                        print("Length: ", len(self.spDB))
##                        print(response["results"])
                    else:
                        print("Not able to fetch....", response["cursor"])
                        return self.spDB
                else:
##                    print("Not able to fetch.... No Cursor")
                    return self.spDB
            return self.spDB
        else:
            return None


    def getRule(self, ruleApi=None):
        if ruleApi == None:
            return None
        api = f"{ruleApi}/statistics?enforcement_point_path=/infra/sites/default/enforcement-points/default"
        return self.getAPI(api=api)

    def getSecurityGroup(self, sgApi=None):
        if sgApi == None:
            return None
        api = f"{sgApi}/statistics?enforcement_point_path=/infra/sites/default/enforcement-points/default"
        return self.getAPI(api=api)

## https://10.40.1.36/policy/api/v1/infra/domains/default/groups

def writeGrp(grpFile, grps):
   fileFound = 0
   # check if file exist, if not pull from api
   # if file exist read data, check for number of records and send a
   # pull request to api server and match with number of records if matched use local file.
   try:
       os.stat(grpFile)
       fileFound = 1
       os.remove(grpFile)
   except FileNotFoundError as e:
         print('File not found') # create a new file and add contents
         fileFound = 0
   if not fileFound: # read from file
    with open(grpFile, "wb") as gfile:
        print("Writing to file data..")
        pickle.dump(grps, gfile)

def readGrp(grpFile):
   fileFound = 0
   # check if file exist, if not pull from api
   # if file exist read data, check for number of records and send a
   # pull request to api server and match with number of records if matched use local file.
   try:
       os.stat(grpFile)
       fileFound = 1
   except FileNotFoundError as e:
         print('File not found') # create a new file and add contents
         return None
   if fileFound: # read from file
     with open(grpFile, "rb") as gfile:
        print("Reading from file for groups...")
        grps = pickle.load(gfile)
        return grps


def connect_and_fetch(nsxObj, api, apid, allgrpsf,lock):
    data = nsxObj.getAPI(api)
    with lock:
        w = {}
        print(apid)
        w.setdefault(apid, data)
        allgrpsf.write(json.dumps(w))
        allgrpsf.write("\n")
        return apid

##            print(w)

def rulePrint(rule, fields, sep="#"):
    i = """f'"""
    sum = ""
    for i in fields:
        sum+=f'{sep}{rule.get(i, None)}'
    return sum



def grpList(grps, start, end):
    grpList = []
    for item in grps:
        if item["display_name"] > start and item["display_name"] < end:
            grpList.append(item)
    print("No of grp to process: ", len(grpList))
    print("="*80)
    return grpList


def createSPList(nsx, filename, sep="#", counter=0):
    # if counter is ZERO all all cases else counter
    spgrps = nsx.getSPList(domainid = "default")
    writeGrp(filename, spgrps)

################### Main #####################
