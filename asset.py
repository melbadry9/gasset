import re
import sys
import time
import queue
import socket
import logging
import traceback
import threading
import multiprocessing

import socks
import requests
from stem import Signal
from stem.control import Controller

logging.getLogger("stem").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.basicConfig(level=logging.DEBUG, filename="gasset.log",format="%(processName)s-%(levelname)s: %(message)s")

#base calsses of enumeration 
class Base(object):
    def __init__(self, domain):
        self.url = ""
        self.BASE_URL =""
        self.domain = domain
        self.proxy = {}
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip'}
        self.done = False
        self.domains = []
        self.adapter = requests.adapters.HTTPAdapter(40, 1, max_retries=2)


    def CreateSession(self):
            self.session = requests.Session()
            self.session.proxies = self.proxy
            self.session.headers = self.HEADERS
            self.session.mount("https://", self.adapter)
            self.session.mount("http://", self.adapter)
            logging.info("New Session created")

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
                    raise AssertionError
            except Exception as t:
                logging.error("Logic Error {}".format(t))
                retry +=1 
   
            if retry <= 5:
                pass
            else:
                done = True

class TorBase(Base):
    lock = threading.Lock()
    def __init__(self, domain):
        Base.__init__(self, domain)
        self.proxy = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
            }
        self.last_change = 0

    def NewTorCircuit(self):
        try:
            if (time.time() - self.last_change) > 10:
                with self.lock:
                    self.last_change = time.time()

                    with Controller.from_port(port=9051) as c:
                        c.authenticate("testtest")
                        c.extend_circuit()
                    logging.info("New circuit created")

                self.session.close()
                self.CreateSession()
        except Exception as err:
            logging.error("Faild to open new circuit {}".format(err))

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

class TorThreaded(multiprocessing.Process, TorBase):
    def __init__(self, domain, shared=None):
        TorBase.__init__(self, domain)
        multiprocessing.Process.__init__(self)
        self.CreateSession()
        self.shared = shared

    def run(self):
        self.Logic(self.url)
        self.shared.extend(self.domains)

class BaseThreaded(multiprocessing.Process, Base):
    def __init__(self, domain, shared=None):
        Base.__init__(self, domain)
        multiprocessing.Process.__init__(self)
        self.CreateSession()
        self.shared = shared

    def run(self):
        self.Logic(self.url)
        self.shared.extend(self.domains)

#children of enumeration sites
class Crt(BaseThreaded):
    def __init__(self, domain, shared=None):
        BaseThreaded.__init__(self, domain, shared)
        self.BASE_URL = "https://crt.sh/?q=%.{domain}&dir=^&sort=1&group=icaid"
        self.url = self.BASE_URL.format(domain=domain)

    def SendRequest(self, url):
        return self.session.get(url, stream=True, timeout=50)
    
    def HandleResponse(self, res):
        sc = res.status_code 
        res = res.text
        if sc == 200:
            regex = r"<TD>([\w\d\.\-\*]+)</TD>"
            subdom = re.findall(regex, res)
            for subdomain in subdom:
                subdomain = subdomain.replace("*.","")
                self.domains.append(subdomain)
                
            self.done = True
            return True
        else:
            return False

class FDNS(BaseThreaded):
    def __init__(self, domain, shared=None):
        BaseThreaded.__init__(self, domain, shared)
        self.BASE_URL = "http://dns.bufferover.run/dns?q=.{domain}"
        self.url = self.BASE_URL.format(domain=domain)
    
    def SendRequest(self, url):
        return self.session.get(url, stream=True)
    
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
    def __init__(self, domain, shared=None):
        TorThreaded.__init__(self, domain, shared)
        self.BASE_URL = 'https://censys.io/certificates/_search?q={domain}&page={page}'
        self.Q = queue.Queue()

    def Logic(self, _):
        for i in range(1,41):
            url = self.BASE_URL.format(domain=self.domain,page=str(i))
            self.Q.put(threading.Thread(target=self.SendRequest, args=(url,)))
        
        while not self.Q.empty():
            self.Q.get().start()

        self.Q.join()
        
    def SendRequest(self, url):
        done = False
        while not done:
            try:
                res = self.session.get(url)
                if res.status_code == 200:
                    self.ExtractDomains(res.text)
                    done = True
                elif res.status_code == 429:
                    self.NewTorCircuit()
            except:
                pass
        self.Q.task_done()

    def ExtractDomains(self, txt):
        scraped = re.findall(r"parsed.names: ([\w\.\-]+)<mark>([\-\w\.]+)",txt)
        for scrap in scraped:
            sdomain = self.Concat(scrap).lower()
            self.domains.append(sdomain)
            
    def Concat(self, re:tuple):
        return re[0] + re[1]

class VirusTotal(TorThreaded):
    def __init__(self, domain, shared=None):
        TorThreaded.__init__(self, domain, shared)
        self.BASE_URL = 'https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40'
        self.url = self.BASE_URL.format(domain=domain)

    def SendRequest(self, url):
        return self.session.get(url)
    
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
                self.domains.append(dom['id'])
            return True
        else:
            return False

class CertSpotter(BaseThreaded):
    def __init__(self, domain, shared=None):
        BaseThreaded.__init__(self, domain, shared)
        self.BASE_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names&include_subdomains=true"
        self.url = self.BASE_URL.format(domain=domain)
    
    def SendRequest(self, url):
        return self.session.get(url)
    
    def HandleResponse(self, res):
        sc = res.status_code 
        res = res.json()
        if sc == 200:
            for item in res:
                for subdomain in item['dns_names']:
                    if (not subdomain.startswith("*")) and (self.domain in subdomain):
                        self.domains.append(subdomain)                    
            self.done = True
            return True
        else:
            return False

def main(domain):
    subdomains_final = multiprocessing.Manager().list()
    active_resources = [Crt, FDNS, VirusTotal, CertSpotter, Censys]
    threads = [resource(domain, subdomains_final) for resource in active_resources]
    
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    
    subdomains_final = set(subdomains_final)
    for sub in subdomains_final:
        print(sub)

if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except IndexError:
        pass