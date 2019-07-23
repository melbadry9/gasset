import re
import sys
import queue
import socket
import threading

import socks
import requests
from stem import Signal
from stem.control import Controller


#base calsses of enumeration 
class Base(object):
    def __init__(self, domain):
        self.done = False
        self.url = ""
        self.BASE_URL =""
        self.domain = domain
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
            }
        self.domains = []
        self.lock = threading.Lock()
        self.c = Controller.from_port(port=9051)
    
    def TorProxyConnect(self):
        try:
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050, True)
            socket.socket = socks.socksocket
        except:
            print("[X] faild to connect to tor")

    def NewTorCircuit(self):
        try:
            self.c.authenticate("testtest")
            self.c.signal(Signal.NEWNYM)
        except:
            print("[x] faild to open new circuit")

    def ChangeIp(self):
        try:
            with self.lock:
                self.NewTorCircuit()
                self.TorProxyConnect()
        except:
            print("[x] faild to change ip")

    def SendRequest(self):
        pass

    def HandleResponse(self):
        pass
    
    def Logic(self,url):
        done = False
        while not done:
            if self.HandleResponse(self.SendRequest(url)):
                done = True
            else:
                self.ChangeIp()

    def Result(self, push):
        if self.done == True:
            if push == 1:
                return self.domains
            else:
                for domain in self.domains:
                    print(domain)

class BaseThreaded(threading.Thread, Base):
    def __init__(self, domain):
        Base.__init__(self, domain)
        threading.Thread.__init__(self)

    def run(self):
        self.Logic(self.url)

#children of enumeration sites
class Crt(BaseThreaded):
    def __init__(self, domain):
        BaseThreaded.__init__(self, domain)
        self.BASE_URL = "https://crt.sh/?q=%.{domain}"
        self.url = self.BASE_URL.format(domain=domain)

    def SendRequest(self, url):
        return requests.get(url, headers=self.HEADERS)
    
    def HandleResponse(self, res):
        sc = res.status_code 
        res = res.text
        if sc == 200:
            regex = r"<TD>([\w\d\.-]+)</TD>"
            subdom = re.findall(regex, res)
            for subdomain in subdom:
                if (subdomain not in self.domains):
                    self.domains.append(subdomain)
                    #print(subdomain)
            self.done = True
            return True
        else:
            return False

class Censys(BaseThreaded):
    def __init__(self, domain):
        BaseThreaded.__init__(self, domain)
        self.BASE_URL = 'https://censys.io/certificates/_search?q={domain}&page={page}'
        self.url = self.BASE_URL.format(domain=domain,page=str(1))
        self.domain = domain

    def SendRequest(self, url):
        return requests.get(url, headers=self.HEADERS)

    def HandleResponse(self, res):
        sc = res.status_code
        res = res.text
        if sc == 200:
            num = re.findall(r"Page: (\d+)\/(\d+)",res)[0]
            scraped = re.findall(r"parsed.names: ([\w\.\-]+)<mark>([\-\w\.]+)",res)
            
            for scrap in scraped:
                sdomain = self.Concat(scrap).lower()
                if sdomain not in self.domains:
                    #print(sdomain)
                    self.domains.append(sdomain)

            if (int(num[0]) == int(num[1])) or (int(num[0]) == 40):
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

class VirusTotal(BaseThreaded):
    def __init__(self, domain):
        BaseThreaded.__init__(self, domain)
        self.BASE_URL = 'https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40'
        self.url = self.BASE_URL.format(domain=domain)

    def SendRequest(self, url):
        return requests.get(url, headers=self.HEADERS)
    
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
                #print(dom['id'])
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
        return requests.get(url, headers=self.HEADERS)
    
    def HandleResponse(self, res):
        sc = res.status_code 
        res = res.json()
        if sc == 200:
            for item in res:
                for subdomain in item['dns_names']:
                    if (not subdomain.startswith("*")) and (subdomain not in self.domains) and (self.domain in subdomain):
                        self.domains.append(subdomain)
                        #print(subdomain)
            self.done = True
            return True
        else:
            return False

def asset(domain):
    subdomains = []
    threads = [VirusTotal(domain), Censys(domain), CertSpotter(domain), Crt(domain)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    for thread in threads:
        for item in thread.Result(1):
            if item not in subdomains:
                subdomains.append(item)
    
    for sub in subdomains:
        print(sub)
    
    return subdomains


if __name__ == "__main__":
    try:
        asset(sys.argv[1])
    except IndexError:
        pass