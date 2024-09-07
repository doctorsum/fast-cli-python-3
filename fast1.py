#!/usr/bin/env python3

'''
Python CLI-tool (without need for a GUI) to measure Internet speed with fast.com
'''

import os
import json
import requests
import sys
import time
from threading import Thread

def gethtmlresult(url, result, index):
    '''
    get the stuff from url in chunks of size CHUNK, and keep writing the number of bytes retrieved into result[index]
    '''
    try:
        with requests.get(url, stream=True) as req:
            CHUNK = 100 * 1024
            i = 1
            for chunk in req.iter_content(CHUNK):
                if not chunk:
                    break
                result[index] = i * CHUNK
                i += 1
    except Exception as e:
        print(f"Error fetching data from {url}: {e}")

def application_bytes_to_networkbits(bytes):
    # convert bytes (at application layer) to bits (at network layer)
    return bytes * 8 * 1.0415

def findipv4(fqdn):
    '''
    find IPv4 address of fqdn
    '''
    import socket
    ipv4 = socket.getaddrinfo(fqdn, 80, socket.AF_INET)[0][4][0]
    return ipv4

def findipv6(fqdn):
    '''
    find IPv6 address of fqdn
    '''
    import socket
    ipv6 = socket.getaddrinfo(fqdn, 80, socket.AF_INET6)[0][4][0]
    return ipv6

def fast_com(verbose=False, maxtime=15, forceipv4=False, forceipv6=False):
    '''
    verbose: print debug output
    maxtime: max time in seconds to monitor speedtest
    forceipv4: force speed test over IPv4
    forceipv6: force speed test over IPv6
    '''
    # go to fast.com to get the JavaScript file
    url = 'https://fast.com/'
    try:
        urlresult = requests.get(url)
    except Exception as e:
        print(f"Error connecting to fast.com: {e}")
        return 0
    
    response = urlresult.text
    jsname = None
    for line in response.split('\n'):
        if 'script src' in line:
            jsname = line.split('"')[1]
            break
    
    if not jsname:
        print("Could not find JavaScript file.")
        return 0

    # From that JavaScript file, get the token:
    url = 'https://fast.com' + jsname
    if verbose:
        print("JavaScript URL is", url)

    try:
        urlresult = requests.get(url)
    except Exception as e:
        print(f"Error fetching JavaScript: {e}")
        return 0
    
    allJSstuff = urlresult.text
    token = None
    for line in allJSstuff.split(','):
        if 'token:' in line:
            token = line.split('"')[1]
            break

    if not token:
        print("Could not find token.")
        return 0

    # With the token, get the (3) speed-test-URLs from api.fast.com (which will be in JSON format):
    baseurl = 'https://api.fast.com/'
    if forceipv4:
        ipv4 = findipv4('api.fast.com')
        baseurl = f'http://{ipv4}/'
    elif forceipv6:
        ipv6 = findipv6('api.fast.com')
        baseurl = f'http://[{ipv6}]/'

    url = f'{baseurl}netflix/speedtest?https=true&token={token}&urlCount=3'
    if verbose:
        print("API URL is", url)

    try:
        urlresult = requests.get(url, timeout=2)
    except Exception as e:
        print(f"Error fetching speed test URLs: {e}")
        return 0

    parsedjson = urlresult.json()
    amount = len(parsedjson)
    if verbose:
        print("Number of URLs:", amount)

    threads = [None] * amount
    results = [0] * amount
    urls = [None] * amount
    for i, jsonelement in enumerate(parsedjson):
        urls[i] = jsonelement['url']

    for i, url in enumerate(urls):
        fqdn = url.split('/')[2]
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET6)
            if verbose:
                print(f"IPv6: {fqdn}")
        except:
            pass

    # Start the threads
    for i in range(len(threads)):
        threads[i] = Thread(target=gethtmlresult, args=(urls[i], results, i))
        threads[i].daemon = True
        threads[i].start()

    # Monitor the amount of bytes (and speed) of the threads
    time.sleep(1)
    sleepseconds = 3
    lasttotal = 0
    highestspeedkBps = 0
    nrloops = maxtime // sleepseconds
    for loop in range(nrloops):
        total = sum(results)
        delta = total - lasttotal
        speedkBps = (delta / sleepseconds) / 1024
        if verbose:
            print(f"Loop {loop}, Total MB {total / (1024 * 1024)}, Delta MB {delta / (1024 * 1024)}, Speed kB/s: {speedkBps}, Mbps: {application_bytes_to_networkbits(speedkBps) / 1024:.1f}")
        
        lasttotal = total
        if speedkBps > highestspeedkBps:
            highestspeedkBps = speedkBps
        time.sleep(sleepseconds)

    Mbps = application_bytes_to_networkbits(highestspeedkBps) / 1024
    Mbps = float(f"{Mbps:.1f}")
    if verbose:
        print(f"Highest Speed (kB/s): {highestspeedkBps}, aka Mbps {Mbps}")

    return Mbps

######## MAIN #################

if __name__ == "__main__":
    print("Let's speed test:")
    print("\nSpeed test, without logging:")
    print(fast_com())
    print("\nSpeed test, with logging:")
    print(fast_com(verbose=True))
    print("\nSpeed test, IPv4, with verbose logging:")
    print(fast_com(verbose=True, maxtime=18, forceipv4=True))
    print("\nSpeed test, IPv6:")
    print(fast_com(maxtime=12, forceipv6=True))
    print("\n30 second speed test:")
    fast_com(verbose=True, maxtime=30)
    print("\ndone")
