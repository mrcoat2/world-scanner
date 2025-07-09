import nmap
import requests # type: ignore
import json

MAIN_SERVER = "http://localhost:8080/"

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
    print("Starting scanner")
    new_scanner = nmap.PortScanner()
    n = new_scanner.scan(hosts=ips, arguments='-n -T4 --min-parallelism 100 --max-retries 1')

    headers = {
        "scanned": ips
    }

    if n['nmap']['scanstats']['uphosts'] == '1':
        print(str(new_scanner[ips]))
        requests.post(MAIN_SERVER+"ips", data=json.dumps(new_scanner[ips]),headers=headers)
    

def work():
    to_do = requests.get(MAIN_SERVER + "todo")
    print(to_do.text)

    check_up(to_do.text)

def main():
    if confirm("This will start the scanner, start?", 'y') != 'y':
        exit()
    
    while(True):
        work()


if __name__ == "__main__":
    main()
