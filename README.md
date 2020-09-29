<h1 align="center">ORhunter</h1>
<p align="center">
    <a href="https://python.org">
    <img src="https://img.shields.io/badge/Python-3.7-green.svg">
  </a>
  <a href="https://github.com/PushpenderIndia/subdover/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg">
  </a>
  <a href="https://github.com/PushpenderIndia/subdover/releases">
    <img src="https://img.shields.io/badge/Release-1.0-blue.svg">
  </a>
    <a href="https://github.com/PushpenderIndia/subdover">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg">
  </a>
</p>

ORhunter is an Open Redirect Vulnerability Scanner which Passively Crawls URLs from 3 Sources &amp; Then Filter Potential URLs based on Parameter Values, then finally hunt them for Unvalidated Open Redirect 

## Disclaimer
<p align="center">
  :computer: This project was created only for good purposes and personal use.
</p>

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. YOU MAY USE THIS SOFTWARE AT YOUR OWN RISK. THE USE IS COMPLETE RESPONSIBILITY OF THE END-USER. THE DEVELOPERS ASSUME NO LIABILITY AND ARE NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE CAUSED BY THIS PROGRAM.

## Features
- [x] Works on Windows/Linux/MacOS
- [x] Passively Crawls URLs from 3 Sources

| Crawl URLs from |
| --------------- |
| Wayback Machine |
| Common Crawl    |
| AlienVault's OTX (Open Threat Exchange) |

- [x] Filter Potentially Vulnerable URLs based on Parameter value
- [x] Replaces only those parameter's value whose parameter value is a URL with "http://evil.com"

> **Example** : Converts this URL to *http://example.com/index.php?r=http://google.com&version=34* to *http://example.com/index.php?r=http://evil.com&version=34*

- [x] If you want to test your own URLs List & don't want to crawl URLs then you can use **--list** flag
- [x] DeepCrawl Feature (If Enabled, then Ragno try to fetch URLs from all **74+ CommonCrawl APIs**)
- [x] MultiThreading 
- [x] Result of **Subdomains** could be excluded & included via CommandLine Argument (i.e. **-s**)
- [x] Save Result in TXT File
- [x] GET Based Unvalidated Open Redirect Vulnerability Scanner
- [x] Path Fragment Unvalidated Open Redirect Vulnerability Scanner [**Under Development**]
 
## Prerequisite
- [x] Python 3.X
- [x] Few External Modules


## Available Arguments 
* Optional Arguments

| Short Hand  | Full Hand       | Description                     |
| ----------  | ---------       | -----------                     |
| -h          | --help          | show this help message and exit |
| -t THREAD   | --thread THREAD | Number of Threads to Used. Default=50 |
| -o OUTPUT   | --output OUTPUT | Save Result in TXT file         |
| -s          | --subs          | Include Result of Subdomains    |
|             | --deepcrawl     | Uses All Available APIs of CommonCrawl for Crawling URLs [Takes Time] |


* Required Arguments

| Short Hand  | Full Hand | Description |
| ----------  | --------- | ----------- |
| -l URL_LIST | --list URL_LIST | URLs List, ex:- google_urls.txt |
| -d DOMAIN   | --domain DOMAIN | Target Domain Name, ex:- google.com |

## How To Use in Linux
```bash
# Navigate to the /opt directory (optional)
$ cd /opt/

# Clone this repository
$ git clone https://github.com/PushpenderIndia/ORhunter.git

# Navigate to ORhunter folder
$ cd ORhunter

# Installing dependencies
$ apt-get update && apt-get install python3-pip
$ pip3 install numpy requests

# Giving Executable Permission
$ chmod +x orhunter.py

# Checking Help Menu
$ python3 orhunter.py --help

# Normal (Fast) URL Crawl + Testing GET based open redirect
$ python3 orhunter.py -d target.com 

# Normal (Fast) URL Crawl + Testing GET based open redirect + Include Subdomain's URLs
$ python3 orhunter.py -d target.com -s

# Normal (Fast) URL Crawl + Testing GET based open redirect + Include Subdomain's URLs + Save Result
$ python3 orhunter.py -d target.com -s -o result.txt

# Run Deep Crawl + Saving Result + Include Subdomain's URLs + Change Thread Number
$ python3 orhunter.py -d target.com -o result.txt -s --deepcrawl --thread 100
```

## How To Use in Windows
```bash
# Install dependencies 
$ Install latest python 3.x from Official Site (https://www.python.org/downloads/)

# Clone this repository or Download Zip File
$ git clone https://github.com/PushpenderIndia/ORhunter.git

# Navigate to ORhunter folder
$ cd ORhunter

# Installing dependencies
$ python -m pip install numpy requests

# Checking Help Menu
$ python orhunter.py --help

# Checking Help Menu
$ python orhunter.py --help

# Normal (Fast) URL Crawl + Testing GET based open redirect
$ python orhunter.py -d target.com 

# Normal (Fast) URL Crawl + Testing GET based open redirect + Include Subdomain's URLs
$ python orhunter.py -d target.com -s

# Normal (Fast) URL Crawl + Testing GET based open redirect + Include Subdomain's URLs + Save Result
$ python orhunter.py -d target.com -s -o result.txt

# Run Deep Crawl + Saving Result + Include Subdomain's URLs + Change Thread Number
$ python orhunter.py -d target.com -o result.txt -s --deepcrawl --thread 100
```

## Screenshot

![](/Result.JPG)

## Contribute

* All Contributors are welcome, this repo needs contributors who will improve this tool to make it best.

## Contact

singhpushpender250@gmail.com 

## Buy Me A Coffee

* Support my Open Source projects by making Donation, It really motivates me to work on more projects
* PayPal Email: `shrisatender@gmail.com` [**Please Don't Send Emails to This Address**]

## More Features Coming Soon...
