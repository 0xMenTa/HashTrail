import os
from dotenv import load_dotenv
from colorama import Fore, Style, Back
import hashtrail

load_dotenv()

def search_urlhaus(suspect_url):
    api_key = os.getenv("URLHAUS_API_KEY")
    if not api_key:
        print(f"{Fore.RED}[✗] URLHaus API key missing")
        return

    url = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {'Auth-Key': api_key}
    data = {"url": suspect_url}

    urlhaus_info = hashtrail.req_post(url, headers, data)
    parse_urlhaus(urlhaus_info)


def parse_urlhaus(urlhaus_info):
    status = urlhaus_info.get('query_status')
    
    if status != "ok":
        if status == "unknown_auth_key":
            print(f"{Fore.RED}[✗] Incorrect API key")
        else:
            print(f"{Fore.YELLOW}[!] Status of the request : {status}")
        return

    tags = urlhaus_info.get('tags', [])
    info = {
        "URL": urlhaus_info.get('url', 'N/A'),
        "URL Status": urlhaus_info.get('url_status', 'N/A'),
        "Threat": urlhaus_info.get('threat', 'N/A'),
        "Tag": ", ".join(tags),
    }
    hashtrail.print_info(info)

    status = urlhaus_info.get('url_status', 'offline')
    status_str = "ONLINE" if status == "online" else "OFFLINE"
    color = Back.GREEN if status == "online" else Back.RED
    print("\n" + color + Fore.BLACK + f"STATUS : {status_str} ".center(70) + Style.RESET_ALL)

    print(f"\n{Fore.CYAN}- Payload delivery -{Style.RESET_ALL}\n")

    payloads = urlhaus_info.get('payloads')
    if not payloads:
        print(f"{Fore.YELLOW}[!] No Payload info available.")
        return

    payload_info = payloads[0]
    payload = {
        "First Seen": payload_info.get('firstseen', 'N/A'),
        "File Type": payload_info.get('file_type', 'N/A'),
        "SHA256": payload_info.get('response_sha256', 'N/A'),
        "VirusTotal Result": payload_info.get('virustotal', {}).get('result', 'N/A'),
        "Signature": payload_info.get('signature', 'N/A'),   
    }
    hashtrail.print_info(payload)
