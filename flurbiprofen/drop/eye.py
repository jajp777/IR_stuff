import ssl
import sys
import json
import time
import whois
import socket
import syslog
import M2Crypto
import requests
import tldextract
import subprocess
#import dns.resolver

from ipwhois import IPWhois
from selenium import webdriver
from elasticsearch import Elasticsearch



def get_whois(doc):
    """we are going to split out the domain from the url and lookup the ip address
        then we get both whois ip and domain name info"""

    #extract domain info
    domain = tldextract.extract(doc['url']).registered_domain
    hostname = doc['url'].split('/')[2]
    doc['hostname'] = hostname
    doc['ip'] = ''
    doc['whois'] = {}

    try:
        #lookup ip address
        doc['ip'] = socket.gethostbyname(hostname)

    except:
        syslog.syslog('[*] Failed to get ip addr for %s' % hostname)
        print('[*] Failed to get ip addr for %s' % hostname) 
        return doc 

    #now lets lookup ip whois
    try:
        doc['whois']['nets'] = IPWhois(doc['ip']).lookup()['nets']

    except:
        syslog.syslog('[*] Failed to get ip whois for %s' % doc['ip'])
        print('[*] Failed to get ip whois for %s' % doc['ip'])

    #now lets try to get domain name registrar
    try:
        doc['whois']['registrar'] = whois.query(domain).registrar

    except:
        syslog.syslog('[*] Failed to get registrar info for %s' % domain) 
        print('[*] Failed to get registrar info for %s' % domain)    

    return doc


def get_certinfo(doc):
    """We are going to see if ssl is available and if so get the certificate
        and parse out subject name, issuer, creation and expiration"""

    #set a two second default timeout to recieve a cert
    socket.setdefaulttimeout(2)
    doc['ssl'] = {}    

    try:
        cert = ssl.get_server_certificate((doc['hostname'], 443))
        #sometimes certs come back as unicode so cast to str() aka ascii
        cert = M2Crypto.X509.load_cert_string(str(cert))

    except:
        syslog.syslog('[*] Failed to get ssl certificate from %s' % doc['hostname'])
        print('[*] Failed to get ssl certificate from %s' % doc['hostname'])
        #lets remove the ssl key and return the doc untouched
        doc.pop('ssl')
        return doc


    #get creation date
    doc['ssl']['created'] = cert.get_not_before().get_datetime().isoformat()
    #get not valid after, aka expiration data
    doc['ssl']['expire'] = cert.get_not_after().get_datetime().isoformat()
    #get issuer information
    doc['ssl']['issuer'] = cert.get_issuer().as_text()
    #get subject information
    doc['ssl']['subject'] = cert.get_subject().as_text()
    #get keysize, size() returns in bytes, so we multiply * 8 to get the number of bits
    doc['ssl']['keysize'] = cert.get_pubkey().size() * 8
    #get cert fingerprint for comparison
    doc['ssl']['fingerprint'] = cert.get_fingerprint()

    return doc



def interrogate_homepage(doc):
    """We are going to use a headless browser to hit the target homepage and
        enumerate all of the other urls that we hit, cookies and the page source"""

    socket.setdefaulttimeout(30)

    doc['browser'] = {}

    #empty page
    empty = u'<html><head></head><body></body></html>'

    #set the path to our compiled phantomjs
    phantomjs = '/phantom_bin/bin/phantomjs'
    #set server args to ignore certificate errors
    serv_arg = ['--ignore-ssl-errors=true']
    ua = ('Mozilla/4.0 (compatible; MSIE 6.01; Windows NT 6.0)')


    driver = webdriver.PhantomJS(phantomjs, 
        service_args=serv_arg, 
        desired_capabilities={
        'phantomjs.page.settings.userAgent' : ua })

    #driver.set_page_load_timeout(10)

    try:
        #going to add a little sleep here, just to make sure phantomjs has finished loading up...
        time.sleep(1)
        driver.get(doc['url'])
        #add the page source to doc
        src = driver.page_source

        #lets check if the page is 'blank', this usually means there is no website
        if src == empty:
            print('[*] Recieved an empty page for url %s ' % (doc['url']))
            #first we are going to see if we hit it over ssl, if so try over http
            if 'https' in doc['url']:
                newurl = doc['url'].replace('https', 'http')

            #if it doesn't have https, so assume http, and there was some ssl stuff returned try https page
            if 'https' not in doc['url'] and doc.has_key('ssl'):
                newurl = doc['url'].replace('http', 'https')

            print('[*] Trying url %s' % newurl)
            driver.get(newurl)
            src = driver.page_source

            if src != empty:
                doc['url'] = newurl

        doc['browser']['src'] = src

        log = json.loads(driver.get_log('har')[0]['message'])
        
        #lets get every url we requested
        tmp = []
        urls = []
        for entry in log['log']['entries']:
            tmp.append(entry['request']['url'])

        #quick dedup
        urls = list(set(tmp))
        
        doc['browser']['urls'] = urls

        #final check to see if our page is empty
        if doc['browser']['src'] == empty:
            doc['browser'].pop('src')

        return doc

    except:
        print('[*] Something went wrong browsing %s falling back to requests' % doc['url'])

        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1'}
            res = requests.get(doc['url'], headers=headers, verify=False)
            doc['browser']['src'] = res.content
            return doc

        except:
            print('[*] Failed to get home page with requests for %s , giving up' % doc['url'])
            doc.pop('browser')
            return doc


def get_ids_logs(doc):
    """this will parse the eve log and get some information from it and add it to 
        our document. We are just going to get the signature name for now"""

    doc['ids'] = []

    with open('/var/log/suricata/eve.json', 'r') as f:
        for line in f:
            #lets go ahead and deserialize the log and pull out sig field
            sig = json.loads(line)['alert']['signature']
            #blergh, too lazy to comment out of suricata, or change UA
            if sig != "ET POLICY Python-urllib/ Suspicious User Agent":
                doc['ids'].append(sig)

    #add a check for empty ids file and lets just remove the field
    if len(doc['ids']) == 0:
        doc.pop('ids')
        return doc

    return doc



def ssl_intercept(doc):
    """this is a helper function to get urls requested when rendering homepage
        will be used for creating /etc/hosts and stunnel entries"""

    urls = doc['browser']['urls']
    
    tmp = []
    for url in urls:
        tmp.append(url.split('/')[2])

    return list(set(tmp))    



def main(url, ip):
    """this function will just combine all of the logic to create our doc and post to elasticsearch"""

    doc = {'url' : url}
    #get the whois and domain info
    print('[*] Getting whois')
    doc = get_whois(doc)

    #only continue checking stuff if we can actually resolve the address
    if doc['ip'] != '':
        #get ssl information if available
        print('[*] Get certificate information')
        doc = get_certinfo(doc)
        #browse to the site and get metrics
        print('[*] Interrogating homepage')
        doc = interrogate_homepage(doc)

        #now it is time to parse the ids logs
        doc = get_ids_logs(doc)

    #strip out ip if we don't have one
    if doc['ip'] == '':
        doc.pop('ip')
    

    try:
        print('[*] Adding information to elastiseach as %s:9200' % ip)
        es = Elasticsearch([ip])
        res = es.index(index='flurb', doc_type='site', body=doc)
        #if res == 'OK then return some sort of success response

        #there is no explicit close so we are going to delete
        #our es object to trigger the socket cleanup
        del(es)

    except:
        print('[*] Failed to add document to elasticsearch at %s' % ip)
        del(es)
        return doc

    return doc



if __name__ == "__main__":

    #docker0 interface ip - change if needed
    es_ip = '172.17.42.1'

    print('[*] Starting IDS')
    #could add some checking here....
    subprocess.call(['service', 'suricata', 'start'])

    #lets just sleep a few seconds to wait for suricata to spin up
    time.sleep(5)

    #call our main function
    print('[*] Starting site analysis')
    doc = main(sys.argv[1], es_ip)
    print doc



