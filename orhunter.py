
import sys
import subprocess
import requests
import argparse
import numpy as np
import threading
import urllib.parse as urlparse
import numpy as np
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

"""
Crawl Source:
=============
1. web.archive.org
2. index.commoncrawl.org
3. otx.alienvault.com  [Under Dev]
"""
    
def get_arguments():
    parser = argparse.ArgumentParser(description=f'{RED} OpenRedirect Hunter v1.0')
    parser._optionals.title = f"{GREEN}Optional Arguments{YELLOW}"
    parser.add_argument("-t", "--thread", dest="thread", help="Number of Threads to Used. Default=50", default=50)
    parser.add_argument("-o", "--output", dest="output", help="Save Vulnerable URLs in TXT file")
    parser.add_argument("-s", "--subs", dest="want_subdomain", help="Include Result of Subdomains", action='store_true')
    parser.add_argument("--deepcrawl", dest="deepcrawl", help="Uses All Available APIs of CommonCrawl for Crawling URLs [**Takes Time**]", action='store_true')
    
    required_arguments = parser.add_argument_group(f'{RED}Required Arguments{GREEN}')
    required_arguments.add_argument("-l", "--list", dest="url_list", help="URLs List, ex:- google_urls.txt")
    required_arguments.add_argument("-d", "--domain", dest="domain", help="Target Domain Name, ex:- google.com")
    return parser.parse_args()

def readTargetFromFile(filepath):
    """
    Returns: Python URLs List
    """
    urls_list = []
    
    with open(filepath, "r") as f:
        for urls in f.readlines():
            if urls != "": 
                urls_list.append(urls.strip())  

    return urls_list  

class PassiveCrawl:
    def __init__(self, domain, want_subdomain, threadNumber, deepcrawl):
        self.domain = domain
        self.want_subdomain = want_subdomain  #Bool
        self.deepcrawl = deepcrawl            #Bool
        self.threadNumber = threadNumber
        self.final_url_list = []
    
    def start(self):
        if self.deepcrawl:
            self.startDeepCommonCrawl()
        else:
            self.getCommonCrawlURLs(self.domain, self.want_subdomain, ["http://index.commoncrawl.org/CC-MAIN-2018-22-index"])
        
        urls_list1 = self.getWaybackURLs(self.domain, self.want_subdomain)
        urls_list2 = self.getOTX_URLs(self.domain)
        
        # Combining all URLs list
        self.final_url_list.extend(urls_list1)
        self.final_url_list.extend(urls_list2)
        
        # Removing Duplicate URLs
        self.final_url_list = list(dict.fromkeys(self.final_url_list))
        
        return self.final_url_list
    
    def getIdealDomain(self, domainName):
        final_domain = domainName.replace("http://", "")
        final_domain = final_domain.replace("https://", "")
        final_domain = final_domain.replace("/", "")
        final_domain = final_domain.replace("www", "")
        return final_domain

    def split_list(self, list_name, total_part_num):
        """
        Takes Python List and Split it into desired no. of sublist
        """
        final_list = []
        split = np.array_split(list_name, total_part_num)
        for array in split:
            final_list.append(list(array))		
        return final_list

    def make_GET_Request(self, url, response_type):
        response = requests.get(url)
        
        if response_type.lower() == "json":
            result = response.json()
        else:
            result = response.text
        
        return result

    def getWaybackURLs(self, domain, want_subdomain):
        if want_subdomain == True:
            wild_card = "*."
        else:
            wild_card = ""
               
        url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"  
        urls_list = self.make_GET_Request(url, "json")
        try:
            urls_list.pop(0)
        except:
            pass
        
        final_urls_list = []
        for url in urls_list:
            final_urls_list.append(url[0])    

        return final_urls_list
        
    def getOTX_URLs(self, domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
        raw_urls = self.make_GET_Request(url, "json")
        urls_list = raw_urls["url_list"]
        
        final_urls_list = []
        for url in urls_list:
            final_urls_list.append(url["url"])
            
        return final_urls_list         

    def startDeepCommonCrawl(self):
        api_list =  self.get_all_api_CommonCrawl()
        collection_of_api_list = self.split_list(api_list, int(self.threadNumber)) 

        thread_list = []
        for thread_num in range(int(self.threadNumber)):   
            t = threading.Thread(target=self.getCommonCrawlURLs, args=(self.domain, self.want_subdomain, collection_of_api_list[thread_num],)) 
            thread_list.append(t)
            
        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()

    def get_all_api_CommonCrawl(self):
        url = "http://index.commoncrawl.org/collinfo.json"
        raw_api = self.make_GET_Request(url, "json")
        final_api_list = []
        
        for items in raw_api:
            final_api_list.append(items["cdx-api"])
        
        return final_api_list

    def getCommonCrawlURLs(self, domain, want_subdomain, apiList):
        if want_subdomain == True:
            wild_card = "*."
        else:
            wild_card = ""
        
        final_urls_list = []
        
        for api in apiList:
            #url = f"http://index.commoncrawl.org/CC-MAIN-2018-22-index?url={wild_card+domain}/*&fl=url"  
            url = f"{api}?url={wild_card+domain}/*&fl=url"     
            raw_urls = self.make_GET_Request(url, "text")
                    
            if ("No Captures found for:" not in raw_urls) and ("<title>" not in raw_urls):
                urls_list = raw_urls.split("\n")

                for url in urls_list:
                    if url != "":
                        self.final_url_list.append(url)          

class OpenRedirectScanner:
    def __init__(self, url_list, threadNumber, domainName):
        self.domainName = domainName
        self.url_list = url_list
        self.threadNumber = threadNumber
        self.vulnerable_urls = []
        self.total_urls_scanned = 0
        self.unique_potential_urls = 0
        self.total_error_encountered = 0
        
    def start(self):
        #===================================================================================================
        # Filtering Those URLs where "=http" is included
        #===================================================================================================
        openredirect_url_list = self.filter_potential_openredirect_urls(self.url_list)
        print("[>>] [Potentially Vulnerable URLs] : ", len(openredirect_url_list))
    
        #===================================================================================================
        # Replacing Parameter value to "http://evil.com"
        #===================================================================================================
        final_openredirect_url_list = []
        for url in openredirect_url_list:
            final_openredirect_url_list.append(self.replace_param_value(url, "http://evil.com", "http"))
        
        #===================================================================================================
        # Sorting Unique URls 
        #===================================================================================================
        final_openredirect_url_list = list(dict.fromkeys(final_openredirect_url_list))
        self.unique_potential_urls = len(final_openredirect_url_list)
        print("[>>] [Unique Potentially Vulnerable URLs] : ", len(final_openredirect_url_list))            
        
        #===================================================================================================
        # Spliting URLs_list in Sub Lists
        #===================================================================================================
        final_openredirect_url_list = self.split_list(final_openredirect_url_list, int(arguments.thread))

        # Scanning Those URLs for OpenRedirect
        print("=========================================================================")
        thread_list = []
        for thread_num in range(int(self.threadNumber)):   
            t = threading.Thread(target=self.scan_urls_for_open_redirect, args=(final_openredirect_url_list[thread_num], self.domainName)) 
            thread_list.append(t)

        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()  

        return self.vulnerable_urls

    def filter_potential_openredirect_urls(self, url_list):
        openredirect_url_list = []
        for url in url_list:
            if "=http" in url:
                openredirect_url_list.append(url)
        return openredirect_url_list 

    def replace_param_value(self, url, newParamValue, keywordInTargetParam):
        """
        Usgae: Replaces Older Parameter Value with New One
        Input: url, newParamValue, keywordInTargetParam
        """
        # print(parsed) ==> ParseResult(scheme='http', netloc='www.example.com', path='', params='', query='type=a&type1=b&type2=c', fragment='')
        parsed = urlparse.urlparse(url)
        querys = parsed.query.split("&")

        result = []
        for param in querys:
            if keywordInTargetParam in param:
                new_param = list(param)
                required_char = []
                
                for char in new_param:
                    if char != "=":
                        required_char.append(char)
                    elif char == "=":
                        break
                        
                new_param_str = ""
                for char in required_char:
                    new_param_str += char
                    
                result.append(new_param_str + "=" + newParamValue)
            else:
                result.append(param)
                
        new_query = "&".join(["{}".format(params) for params in result])
        parsed = parsed._replace(query=new_query)
        final_url = urlparse.urlunparse(parsed)
        return final_url 

    def split_list(self, list_name, total_part_num):
        """
        Takes Python List and Split it into desired no. of sublist
        """
        final_list = []
        split = np.array_split(list_name, total_part_num)
        for array in split:
            final_list.append(list(array))		
        return final_list 
        
    def scan_urls_for_open_redirect(self, url_list, domainNameOfTarget):
        for url in url_list:
            try:
                r = requests.get(str(url), allow_redirects=False, verify=False)
                if r.status_code in [301, 302, 303, 304, 305, 306, 307, 308]:
                    if ("evil.com" in r.headers["Location"]) and ("=http://evil.com" not in r.headers["Location"]) and (domainNameOfTarget not in r.headers["Location"]):
                        self.vulnerable_urls.append(url)
            except:
                self.total_error_encountered += 1

            self.total_urls_scanned += 1
            print(f"[>>] [Total URLs Scanned] : {self.total_urls_scanned}/{self.unique_potential_urls} | [>>] [Total Error Encountered] : {self.total_error_encountered}", end="\r")
    
if __name__ == '__main__':
    arguments = get_arguments() 
    
    if arguments.domain:
        # Crawling Target URLs from 3 Sources
        print("=========================================================================")
        print("[>>] Crawling URLS from : WaybackMachine, AlienValut OTX, CommonCrawl ...")
        crawl = PassiveCrawl(arguments.domain, arguments.want_subdomain, arguments.thread, arguments.deepcrawl)
        final_url_list = crawl.start()
        
    elif arguments.url_list: 
        final_url_list = readTargetFromFile(arguments.url_list)
    
    else:
        print("[!] Please Specify --domain or --list flag ..")
        print(f"[*] Type : {sys.argv[0]} --help")
        sys.exit()
    
    print("=========================================================================")
    print("[>>] [Total URLs] : ", len(final_url_list))   
    
    # Scanning targets using OpenRedirectScanner class
    scan = OpenRedirectScanner(final_url_list, arguments.thread, arguments.domain)
    vulnerable_urls = scan.start()
    print("\n=========================================================================")
    for urls in vulnerable_urls:
        print(urls)
    print("\n[>>] [Total Confirmed URLs] : ", len(vulnerable_urls))
        
    if arguments.output:
        with open(arguments.output, "w") as f:
            for url in vulnerable_urls:
                f.write(url+"\n")
                
                
        
       


