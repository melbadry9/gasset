import re
import sys
import queue
import socket
import logging
import threading
import multiprocessing

import socks
import requests
from stem import Signal
from stem.control import Controller

logging.basicConfig(level=logging.DEBUG, filename="data.log",format="%(processName)s-%(levelname)s: %(message)s")


#base calsses of enumeration 
class Base(object):
    def __init__(self, domain):
        self.url = ""
        self.BASE_URL =""
        self.proxy = {}
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
            }
        self.done = False
        self.domains = []
        self.domain = domain
        
    def SendRequest(self):
        pass

    def HandleResponse(self):
        pass
    
    def Logic(self, url):
        retry = 0  
        done = False
        while not done:
            logging.debug("Requesting[{}]: {}".format(str(retry), url))
            try:
                if self.HandleResponse(self.SendRequest(url)):
                    done = True
                else:
                    raise Exception
            except Exception as t:
                error_msg = "Logic Error {}".format(str(t))
                logging.error(error_msg)
                retry +=1 
   
            if retry <= 5:
                pass
            else:
                done = True

    def Result(self, push=0):
        if push == 1:
            return self.domains
        else:
            for domain in self.domains:
                print(domain)

class TorBase(Base):
    def __init__(self, domain):
        Base.__init__(self, domain)
        self.proxy = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
            }
        self.lock = threading.Lock()
        self.c = Controller.from_port(port=9051)

    def NewTorCircuit(self):
        try:
            self.c.authenticate("testtest")
            self.c.signal(Signal.NEWNYM)
            #self.extend_circuit(0)
            logging.info("New circuite created")
        except:
            logging.error("Faild to open new circuit")

    def Logic(self, url):
        done = False
        while not done:
            logging.debug("Requesting: {}".format(url))
            try:
                if self.HandleResponse(self.SendRequest(url)):
                    done = True
                else:
                    self.NewTorCircuit()
            except Exception as t:
                error_msg = "Logic Error {}".format(str(t))
                logging.error(error_msg)

class TorThreaded(threading.Thread, TorBase):
    def __init__(self, domain):
        TorBase.__init__(self, domain)
        threading.Thread.__init__(self)

    def run(self):
        self.Logic(self.url)

class BaseThreaded(multiprocessing.Process, Base):
    def __init__(self, domain):
        Base.__init__(self, domain)
        multiprocessing.Process.__init__(self)

    def run(self):
        self.Logic(self.url)

#children of enumeration sites
class Crt(BaseThreaded):
    def __init__(self, domain):
        BaseThreaded.__init__(self, domain)
        self.BASE_URL = "https://crt.sh/?q=%.{domain}&dir=^&sort=1&group=icaid"
        self.url = self.BASE_URL.format(domain=domain)

    def SendRequest(self, url):
        return requests.get(url, headers=self.HEADERS, stream=True, timeout=50, proxies=self.proxy)
    
    def HandleResponse(self, res):
        sc = res.status_code 
        res = res.text
        if sc == 200:
            regex = r"<TD>([\w\d\.\-\*]+)</TD>"
            subdom = re.findall(regex, res)
            for subdomain in subdom:
                subdomain = subdomain.replace("*.","")
                if (subdomain not in self.domains):
                    self.domains.append(subdomain)
                    print(subdomain)
            self.done = True
            return True
        else:
            return False

class FDNS(BaseThreaded):
    def __init__(self, domain):
        BaseThreaded.__init__(self, domain)
        self.BASE_URL = "http://dns.bufferover.run/dns?q=.{domain}"
        self.url = self.BASE_URL.format(domain=domain)
    
    def SendRequest(self, url):
        return requests.get(url, headers=self.HEADERS, stream=True, proxies=self.proxy)
    
    def HandleResponse(self, res):
        sc = res.status_code 
        res = res.json()
        if sc == 200:
            for item in res['FDNS_A']:
                item = item.split(",")[1]
                self.domains.append(item)
            self.done = True
            return True
        else:
            return False

class Censys(TorThreaded):
    def __init__(self, domain):
        TorThreaded.__init__(self, domain)
        self.BASE_URL = 'https://censys.io/certificates/_search?q={domain}&page={page}'
        self.url = self.BASE_URL.format(domain=domain,page=str(1))

    def SendRequest(self, url):
        return requests.get(url, headers=self.HEADERS , proxies=self.proxy)

    def HandleResponse(self, res):
        sc = res.status_code
        res = res.text
        if sc == 200:
            num = re.findall(r"Page: (\d+)\/([\d\,]+)",res)[0]
            scraped = re.findall(r"parsed.names: ([\w\.\-]+)<mark>([\-\w\.]+)",res)
            
            for scrap in scraped:
                sdomain = self.Concat(scrap).lower()
                if sdomain not in self.domains:
                    print(sdomain)
                    self.domains.append(sdomain)

            if (int(num[0]) == int(num[1].replace(",",""))) or (int(num[0]) == 40):
                self.done = True
            else:
                self.Logic(self.BASE_URL.format(domain=self.domain, page=str(int(num[0])+1)))

            return True
        elif sc == 400:
            self.done = True
            return True
        else:
            return False

    def Concat(self, re:tuple):
        return re[0] + re[1]

class VirusTotal(TorThreaded):
    def __init__(self, domain):
        TorThreaded.__init__(self, domain)
        self.BASE_URL = 'https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40'
        self.url = self.BASE_URL.format(domain=domain)

    def SendRequest(self, url):
        return requests.get(url, headers=self.HEADERS, proxies=self.proxy)
    
    def HandleResponse(self, res):
        sc = res.status_code
        js = res.json()
        
        if sc == 200:
            try:
                next_url = js['links']['next']
            except KeyError:
                next_url = None
                self.done = True
            
            if next_url:
                self.Logic(next_url)

            for dom in js['data']:
                print(dom['id'])
                self.domains.append(dom['id'])
            return True
        else:
            return False

class CertSpotter(BaseThreaded):
    def __init__(self, domain):
        BaseThreaded.__init__(self, domain)
        self.BASE_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names&include_subdomains=true"
        self.url = self.BASE_URL.format(domain=domain)
    
    def SendRequest(self, url):
        return requests.get(url, headers=self.HEADERS, proxies=self.proxy)
    
    def HandleResponse(self, res):
        sc = res.status_code 
        res = res.json()
        if sc == 200:
            for item in res:
                for subdomain in item['dns_names']:
                    if (not subdomain.startswith("*")) and (subdomain not in self.domains) and (self.domain in subdomain):
                        self.domains.append(subdomain)
                        print(subdomain)
            self.done = True
            return True
        else:
            return False

def asset(domain):
    threads = [Crt(domain), FDNS(domain), Censys(domain), VirusTotal(domain), CertSpotter(domain)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    try:
        asset(sys.argv[1])
    except IndexError:
        pass