import os
from dotenv import load_dotenv
from colorama import Fore, Style
import hashtrail

load_dotenv()

def search_filescan(hash256):
    url = f"https://www.filescan.io/api/reputation/hash?sha256={hash256}"
    filescan_info = hashtrail.req_get(url)
    parse_filescan(filescan_info)

def ai_report_filescan(report_id):
    hashtrail.print_header(4)
    api_key = os.getenv("FILESCAN_API_KEY")
    if not api_key:
        print(f"{Fore.RED}[✗] Filescan API key missing")
        return

    url = f"https://www.filescan.io/api/ai/report/summary?report_id={report_id}"
    headers = {'X-Api-Key': api_key}

    filescan_ai_info = hashtrail.req_get(url, headers)
    parse_filescan_ai(filescan_ai_info)
    #print(filescan_ai_info)

def parse_filescan(data):
    verdict = data.get('overall_verdict', 'N/A')

    filescan_reports = data.get("filescan_reports", [])
    if not filescan_reports:
        print(f"{Fore.YELLOW}[!] No Filescan report available.")
        return

    report_id = filescan_reports[0].get("report_id", None)
    if not report_id:
        print(f"{Fore.YELLOW}[!] Report ID missing from Filescan report.")
        return

    info = {
        "Total AV Engines": data.get('mdcloud', {}).get('total_av_engines', 'N/A'),
        "Detected AV Engines": data.get('mdcloud', {}).get('detected_av_engines', 'N/A'),
        "Scan Time": data.get('mdcloud', {}).get('scan_time', 'N/A'),
    }

    hashtrail.print_info(info)
    hashtrail.print_verdict(verdict)

    try:
        ai_report_filescan(report_id)
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Could not fetch AI report: {e}")

def parse_filescan_ai(data):
    ai_info = data.get("data")
    if not ai_info:
        print(f"{Fore.YELLOW}[!] No AI report data available.")
        return
    
    ai_info_cleaned = ai_info.replace('*', '')

    print(ai_info_cleaned + '\n')
    
