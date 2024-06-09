#-------------------------------------------------------------------------------
# Name:        Collect all Security Policies
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

class myNSX:
    # create for the ops of NSX4 tasks
    # required requests
    def __init__(self, nsxmgr, username = "admin", password = ""):

        self.hostname = nsxmgr
        self.username = username
        self.password = password
        cred = self.getEncoded()
        self.headers = {
          'Accept-Encoding': 'gzip',
          'Content-Type': "application/json",
          'Accept': 'application/json',
          'Connection': 'keep-alive',
          # 'Authorization': "Basic dnBhbmthajpCbHVlYmVycnkjMTQyMjA="
          'Authorization': f'Basic {cred}'
        }
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

        self.baseUrl = f"https://{self.hostname}/policy/api/v1"
        # self.getallServices()

    def __do(self, method="GET", api="", payload={}):
        url = f"{self.baseUrl}{api}"
        # print(url)
        if method == "GET":
          response = self.s.get(url, headers = self.headers )
          if response.status_code >= 200 and response.status_code <= 299:
            return response.json()
          else:
            return "Not able to GET api, please check for login/ip/credentials!!"
    def getAPI(self, api):
        sleep(.5)
        return self.__do(method="GET", api=api, payload={})

    def getEncoded(self):
        # import encoding
        from base64 import b64encode
        s = f'{self.username}:{self.password}'.encode('utf-8')
        return b64encode(s)

    def getGroups(self, domainid = "default"):
##        >>> res.keys()
##        dict_keys(['results', 'result_count', 'sort_by', 'sort_ascending', 'cursor'])
##        >>> res1.keys()
##        dict_keys(['results', 'sort_by', 'sort_ascending', 'cursor'])
        domainid = "default"
        cursor = 0
        api = f'/infra/domains/{domainid}/groups?page_size=1000'
        print("-*-"*25)
        print("Collecting All Groups ...")
        response = self.__do(method="GET", api=api)
        self.grpDB = []
        if "results" in response:
            # collect only name, id, and path
            # Note::::: Group name are case sensitive
            self.grpDB.extend(response["results"])
            totalRecords  = response["result_count"]
            print("Number of records: ", totalRecords)
            while 1:
                if "cursor" in response:
                    cursor = response["cursor"]
##                    print("Cursor: ", response["cursor"])
                    api = f'/infra/domains/{domainid}/groups?cursor={cursor}&page_size=1000'
                    response = self.__do(method="GET", api=api)
                    if "results" in response:
                        self.grpDB.extend(response["results"])
##                        print("Length: ", len(self.grpDB))
##                        print(response["results"])
                    else:
                        print("Not able to fetch....", response["cursor"])
                        return self.grpDB
                else:
##                    print("Not able to fetch.... No Cursor")
                    return self.grpDB
            return self.grpDB
        else:
            return None


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

    def getSP(self, api = "", domainid = "default"):
        cursor = 0
##        api = f'/infra/domains/{domainid}/security-policies/{}'
        print("Collecting security-policies details...")
        response = self.__do(method="GET", api=api)
        if "results" in response:
            return response['results']
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

def getSPAll(msxhost, splistfile=None, spgrpsFile=None):
    counter = 1
    # file = r"C:\work\emerson\10.40.1.31_allgrps_Apr_25_17_14_19.csv"
    lines = readGrp(splistfile)
##    spgrpsFile = f"{msxhost.hostname}_spgrps_{filetime}.txt"
    recordFile = open(spgrpsFile, "w")
    q = []
    with tPool(max_workers=10) as taskexe:
        tasks = { taskexe.submit(connect_and_fetch, msxhost, item["path"], item['id'], recordFile, lock) for item in lines }
    for item in concurrent.futures.as_completed(tasks):
        # r = item.result()
        q.append(item.result())

def getSPRules_ORG(msxhost, rulesFile=None,):
    counter = 1
    # lines = readGrp(rulesFile)
    # rulesFile = f"{msxhost.hostname}_rules_{filetime}.txt"
    recordFile = open(rulesFile, "w")
    q = []
    print("inside ")
    with open(rulesFile, "r") as f:
        lines = f.readlines()
        for line in lines:
            line = json.dumps(line)
            rules = line.get("rules",None)
            print(line)
            if rules == None:

                pass
            else:
                with tPool(max_workers=10) as taskexe:
                    tasks = { taskexe.submit(connect_and_fetch, msxhost, item["path"], item['id'], recordFile, lock) for item in rules }
                for item in concurrent.futures.as_completed(tasks):
                    # r = item.result()
                    q.append(item.result())

def getSP(msxhost, file=None,):
    counter = 1
    # file = r"C:\work\emerson\10.40.1.31_allgrps_Apr_25_17_14_19.csv"
    lines = readGrp(file)
    rulesFile = f"{msxhost.hostname}_rules_{filetime}.txt"
    recordFile = open(rulesFile, "w")
    q = []
    for line in lines:
        rules = line.get("rules",None)
        print(line)
        if rules == None:
            pass
        else:
            with tPool(max_workers=10) as taskexe:
                tasks = { taskexe.submit(connect_and_fetch, msxhost, item["path"], item['id'], recordFile, lock) for item in rules }
            for item in concurrent.futures.as_completed(tasks):
                # r = item.result()
                q.append(item.result())

def getRulesORG(msxhost, file=None,):
    counter = 1
    # file = r"C:\work\emerson\10.40.1.31_allgrps_Apr_25_17_14_19.csv"
    lines = readGrp(file)
    rulesFile = f"{msxhost.hostname}_rules_{filetime}.txt"
    recordFile = open(rulesFile, "w")
    q = []
    for line in lines:
        # print("-"*30)
        d = json.loads(line)
        dnested = d[list(d.keys())[0]]
        rules = dnested.get("rules",None)
##        spprint = rulePrint(dnested, ["display_name","id","path","category","rule_count","resource_type","logging_enabled"])
        if rules == None:
            # print(f'{dnested["display_name"]}#{dnested["id"]}#{dnested["path"]}#{dnested["unique_id"]}#{dnested["category"]}#{dnested["scope"]}#{dnested["rule_count"]}#{dnested["resource_type"]}#{dnested["logging_enabled"]}#{rules}')
            print(spprint)
        else:
            with tPool(max_workers=15) as taskexe:
                tasks = { taskexe.submit(connect_and_fetch, msxhost, item["path"], item['id'], recordFile, lock) for item in rules }
            for item in concurrent.futures.as_completed(tasks):
                # r = item.result()
                q.append(item.result())

##                    rprint = rulePrint(rule, ["display_name", "id", "path", "action", "rule_id", "logged", "disabled"])
####                    r = msxhost.getRule(rule["path"])
##                    if isinstance(r, (str,)):
##                        continue
##                    if r.get('results', None) and r['results'][0].get("statistics", None):
##                        rstat = rulePrint( r['results'][0]["statistics"], ["internal_rule_id", "packet_count", "byte_count", "session_count", "hit_count"])
##                        print(f'{spprint}{rprint}{rstat}')
##                    else:
##                        print(f'{spprint}{rprint}None')
##
##                    counter +=1
####                    if counter == 7:
####                        sys.exit(5)
##
##q.append(item.result())


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


def getSPRules(msxhost, spgrpsFile=None,sprulesFile=None):
##    spgrpsFile = r"C:\work\emerson\10.40.17.31_spgrps_Apr_27_17_32_02.txt"
    # sprulesFile = f"{nsxhostname}_rules_{filetime}.txt"
    ruleslist = []
    prefix = 'cas-'
    q = []
    recordFile = open(sprulesFile, "w")
    with open(spgrpsFile) as f:
        lines = f.readlines()
    for line in lines:
        d = json.loads(line)
        rules = d[next(iter(d))].get("rules", None)
        if rules != None:
            with tPool(max_workers=20) as taskexe:
                tasks = { taskexe.submit(connect_and_fetch, msxhost,
                    f'{item["path"]}/statistics?enforcement_point_path=/infra/sites/default/enforcement-points/default',
                    f'{prefix}{item["id"]}', recordFile, lock) for item in rules }
                sleep(5)
            for item in concurrent.futures.as_completed(tasks):
                # r = item.result()
                q.append(item.result())

##            # process rules
##            for rule in rules:
##                print(f'{prefix}{rule['id']}', rule['path'])
##                ruleslist.append(rule['id'])

        else:
            print(f"No rules found in {d[next(iter(d))]['display_name']}")
    return ruleslist

def getSPRulesBreak(msxhost, spgrpsFile=None,sprulesFile=None, spname=None):
##    spgrpsFile = r"C:\work\emerson\10.40.17.31_spgrps_Apr_27_17_32_02.txt"
    # sprulesFile = f"{nsxhostname}_rules_{filetime}.txt"
    ruleslist = []
    prefix = 'cas-'
    q = []
    recordFile = open(sprulesFile, "w")
    with open(spgrpsFile) as f:
        lines = f.readlines()
    for line in lines:
        d = json.loads(line)
        display_name = d[next(iter(d))].get("display_name", None)
        if display_name >= spname:
            rules = d[next(iter(d))].get("rules", None)
            if rules != None:
                with tPool(max_workers=10) as taskexe:
                    tasks = { taskexe.submit(connect_and_fetch, msxhost,
                        f'{item["path"]}/statistics?enforcement_point_path=/infra/sites/default/enforcement-points/default',
                        f'{prefix}{item["id"]}', recordFile, lock) for item in rules }

                for item in concurrent.futures.as_completed(tasks):
                    # r = item.result()
                    q.append(item.result())

##            # process rules
##            for rule in rules:
##                print(f'{prefix}{rule['id']}', rule['path'])
##                ruleslist.append(rule['id'])

            else:
                print(f"No rules found in {d[next(iter(d))]['display_name']}")
        else:
            continue
    return ruleslist
################### Main #####################
def nsxMain(nsxhostname, username,password):
    splistfile = f"{nsxhostname}_splist_{filetime}.pickle"
    spgrpsFile = f"{nsxhostname}_spgrps_{filetime}.txt"
    sprulesFile = f"{nsxhostname}_rules_{filetime}.txt"
    nsx36 = myNSX(nsxhostname,username,password)
    createSPList(nsx36, splistfile)
    getSPAll(nsx36, splistfile=splistfile, spgrpsFile=spgrpsFile)
    getSPRules(nsx36, spgrpsFile=spgrpsFile,sprulesFile=sprulesFile)
