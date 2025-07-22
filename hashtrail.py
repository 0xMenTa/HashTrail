#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
hashtrail.py

Description : Searching hash SHA256 in Malware Database
Auteur      : MenTa
Date        : 2025
Usage       : python hashtrail.py [SHA256 ...]
"""

import re
import requests
import argparse
from colorama import init, Fore, Style

init(autoreset=True)

ASCII_ART = r"""
                  __            __   __           _ __              
 a'!   _,,_      / /  ___ ____ / /  / /________ _(_) / ___  __ __    
  \\_/    \     / _ \/ _ `(_-</ _ \/ __/ __/ _ `/ / / / _ \/ // /    
   \, /-( /'-, /_//_/\_,_/___/_//_/\__/_/  \_,_/_/_(_) .__/\_, /
   //\ //\\                                         /_/   /___/         
"""

# ----------------------------------------------------------------------
# Utils
# ----------------------------------------------------------------------

def is_valid_sha256(hash_str):
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", hash_str))

def print_info(info_dict):
    for key, value in info_dict.items():
        print(f"[+] {key.ljust(22)}: {value}")

# ----------------------------------------------------------------------
# MalwareBazaar API
# ----------------------------------------------------------------------

def search_malbazaar(hash256):
    api_key = '[API]'
    if not api_key:
        print(f"{Fore.RED}[✗] MalwareBazaar API key missing")
        return

    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {'Auth-Key': api_key}
    data = {"query": "get_info", "hash": hash256}

    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        print(f"[✓] MalwareBazaar HTTP Response : {Fore.GREEN}OK\n")
        parse_malbazaar(response.json())
    except requests.RequestException as e:
        print(f"{Fore.RED}[✗] MalwareBazaar API error : {e}")

def parse_malbazaar(data):
    status = data.get('query_status')
    if status == "ok":
        entry = data['data'][0]
        tags = entry.get('tags', [])
        info = {
            "SHA256": entry.get('sha256_hash'),
            "File Name": entry.get('file_name'),
            "File Type": entry.get('file_type'),
            "Signature": entry.get('signature'),
            "Tags": ", ".join(tags),
            "MalwareBazaar Link": f"https://bazaar.abuse.ch/sample/{entry.get('sha256_hash')}/"
        }
        print_info(info)
    elif status == "unknown_auth_key":
        print(f"{Fore.RED}[✗] Incorrect API key")
    else:
        print(f"{Fore.YELLOW}[!] Status of the request : {status}")

# ----------------------------------------------------------------------
# Filescan.io API
# ----------------------------------------------------------------------

def search_filescan(hash256):
    url = f"https://www.filescan.io/api/reputation/hash?sha256={hash256}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        print(f"\n[✓] Filescan.io HTTP Response : {Fore.GREEN}OK\n")
        parse_filescan(response.json())
    except requests.RequestException as e:
        print(f"{Fore.RED}[✗] Filescan.io API error : {e}")

def parse_filescan(data):
    verdict = data.get('filescan_reports', [{}])[0].get('verdict', 'N/A')
    verdict_color = Fore.GREEN if verdict == 'clean' else Fore.RED if verdict == 'malicious' else Fore.YELLOW
    info = {
        "Total AV Engines": data.get('mdcloud', {}).get('total_av_engines', 'N/A'),
        "Detected AV Engines": data.get('mdcloud', {}).get('detected_av_engines', 'N/A'),
        "Verdict": f"{verdict_color}{verdict}"
    }
    print_info(info)

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Search for SHA256 in MalwareBazaar and Filescan.io")
    parser.add_argument("sha256", nargs="+", help="SHA256 hash(es) to search for")
    args = parser.parse_args()

    print(ASCII_ART)

    for hash256 in args.sha256:
        print(f"{Style.BRIGHT}[+] Search for : {hash256}")
        if not is_valid_sha256(hash256):
            print(f"{Fore.RED}[✗] Invalid SHA256 hash : {hash256}\n")
            continue

        search_malbazaar(hash256)
        print("\n" + "-" * 70 + "\n")
        search_filescan(hash256)
        print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    main()
