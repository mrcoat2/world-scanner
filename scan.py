import nmap
import requests # type: ignore
import json
import random
import ipaddress
from concurrent.futures import ThreadPoolExecutor

MAIN_SERVER = "http://localhost:8080/"

def get_rand_ip():
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, 2**32 -1))
        if not (
            ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local):
            return str(ip)

def confirm(message, choice):
    chosen = choice
    if choice.lower() == "y":
        chosen = input(message + " (Y/n): ")
    else:
        chosen = input(message + " (y/N): ")

    if chosen.lower() != 'y' and chosen.lower() != 'n':
        return choice
    else:
        return chosen.lower()

def check_up(ips: str):
    new_scanner = nmap.PortScanner()
    n = new_scanner.scan(hosts=ips, arguments='-sV -n -T4 --min-parallelism 100 --max-retries 1')

    headers = {
        "scanned": ips
    }

    if not 'tcp' in json.dumps(new_scanner[ips]):
        return

    if n['nmap']['scanstats']['uphosts'] == '1':
        print(str(new_scanner[ips]))
        requests.post(MAIN_SERVER+"ips", data=json.dumps(new_scanner[ips]),headers=headers)
    
def create_worker_threads(count=200, threads=50):
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in range(count):
            ip = get_rand_ip()
            executor.submit(check_up, ip)

def main():
    if confirm("This will start the scanner, start?", 'y') != 'y':
        exit()
    
    while True:
        create_worker_threads()


if __name__ == "__main__":
    main()
