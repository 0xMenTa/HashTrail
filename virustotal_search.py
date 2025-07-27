import os
from dotenv import load_dotenv
from colorama import Fore, Style
from datetime import datetime, timezone
import base64
import hashtrail


load_dotenv()

def format_timestamp(ts):
    if ts != "N/A":
        return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if ts else "Non disponible"
    else:
        return("N/A")


def search_virustotal(hash256=None, mal_url=None):

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print(f"{Fore.RED}[✗] Virus Total API key missing")
        return

    if hash256 != None:
        url = f"https://www.virustotal.com/api/v3/files/{hash256}"

        headers = {
            "x-apikey": api_key  
        }

        virustotal_info = hashtrail.req_get(url, headers)
        parse_virus_total(virustotal_info)
        
    
    if mal_url != None:
        mal_url = base64.urlsafe_b64encode(mal_url.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{mal_url}"

        headers = {
            "x-apikey": api_key  
        }
        
        virustotal_info = hashtrail.req_get(url, headers)
        parse_url_virus_total(virustotal_info)

def parse_virus_total(virustotal_info):

    try:
        entry = virustotal_info.get("data", {}).get("attributes", {})
    except (IndexError, KeyError, TypeError) as e:
        print(f"{Fore.YELLOW}[!] No Virus Total info available. Error: {e}")
        return
    
    tags = entry.get('tags', [])
    info = {
        "Name": entry.get('meaningful_name', 'N/A'),
        "Type": entry.get('type_description', 'N/A'),
        "Tags": ", ".join(tags),
        "VirusTotal Scan URL": "https://www.virustotal.com/gui/file/" +  entry.get('sha256')
    }
    hashtrail.print_info(info)
    print(f"\n{Fore.CYAN}- History -{Style.RESET_ALL}\n")

    date_info = {
        "Times Submitted": entry.get('times_submitted', 'N/A'),
        "Unique Sources": entry.get('unique_sources', 'N/A'),
        "First submission date": format_timestamp(entry.get('first_submission_date','N/A')),
        "Last submission date": format_timestamp(entry.get('last_submission_date','N/A')),
    }
    hashtrail.print_info(date_info)

    print(f"\n{Fore.CYAN}- Antivirus Detection -{Style.RESET_ALL}\n")
    detection_stats = entry.get('last_analysis_stats', {})
    hashtrail.print_info(detection_stats)

def parse_url_virus_total(virustotal_info):
    try:
        entry = virustotal_info.get("data", {}).get("attributes", {})
    except (IndexError, KeyError, TypeError) as e:
        print(f"{Fore.YELLOW}[!] No Virus Total info available. Error: {e}")
        return

    info = {
        "URL": entry.get("url", "N/A"),
        "Last final URL": entry.get("last_final_url", "N/A"),
        "Reputation": entry.get("reputation", "N/A"),
        "Threat Names": ", ".join(entry.get("threat_names", [])) or "N/A",
        "Tags": ", ".join(entry.get("tags", [])) or "N/A",
        "Votes Harmless": entry.get("total_votes", {}).get("harmless", 0),
        "Votes Malicious": entry.get("total_votes", {}).get("malicious", 0),
    }

    hashtrail.print_info(info)

    print(f"\n{Fore.CYAN}- History -{Style.RESET_ALL}\n")

    history = ({
        "Last modification date": format_timestamp(entry.get("last_modification_date")),
        "Last analysis date": format_timestamp(entry.get("last_analysis_date")),
        "First submission date": format_timestamp(entry.get("first_submission_date")),
        "Last submission date": format_timestamp(entry.get("last_submission_date")),
        "Times submitted": entry.get("times_submitted", "N/A"),
    })

    hashtrail.print_info(history)

    print(f"\n{Fore.CYAN}- Antivirus Detection -{Style.RESET_ALL}\n")

    stats = entry.get("last_analysis_stats", {})
    analysis = ({
        "Analysis malicious": stats.get("malicious", 0),
        "Analysis harmless": stats.get("harmless", 0),
        "Analysis undetected": stats.get("undetected", 0),
        "Analysis suspicious": stats.get("suspicious", 0),
    })
    hashtrail.print_info(analysis)


