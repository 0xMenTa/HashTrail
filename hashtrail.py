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
from dotenv import load_dotenv
import os
from colorama import init, Fore, Style, Back

import malwarebazaar_search
import filescanio_search

init(autoreset=True)

ASCII_ART = r"""
                  __            __   __           _ __              
 a'!   _,,_      / /  ___ ____ / /  / /________ _(_) / ___  __ __    
  \\_/    \     / _ \/ _ `(_-</ _ \/ __/ __/ _ `/ / / / _ \/ // /    
   \, /-( /'-, /_//_/\_,_/___/_//_/\__/_/  \_,_/_/_(_) .__/\_, /
   //\ //\\                                         /_/   /___/        

    Basic malware checker in Python
    MenTa - 2025
"""

# ----------------------------------------------------------------------
# Utils
# ----------------------------------------------------------------------

def is_valid_sha256(hash_str):
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", hash_str))

def print_header(header):
    header_dict = {
        1:" HASH ANALYSIS ",
        2:" MALWARE BAZAAR RESEARCH ",
        3:" FILESCAN.IO RESEARCH ",
        4:" AI RESUME "
    }

    print(Back.WHITE + Fore.BLACK + header_dict[header].center(68) + Style.RESET_ALL + "\n")

def req_post(url, headers=None, data=None):
    try:
        response = requests.post(url, headers=headers, data=data)
        return response.json()
    except requests.RequestException as e:
        print(f"{Fore.RED}[✗] HTTP error : {e}")
        return None

def req_get(url, headers=None, data=None):
    try:
        response = requests.get(url, headers=headers, data=data)
        return response.json()
    except requests.RequestException as e:
        print(f"{Fore.RED}[✗] HTTP error : {e}")
        return None
    
def print_info(info_dict):
    for key, value in info_dict.items():
        if value is None:
            value = "N/A"
        print(f"{Fore.LIGHTYELLOW_EX}{key:<25}{Style.RESET_ALL}: {Fore.WHITE}{value:<45}{Style.RESET_ALL}")

def print_verdict(verdict):
    verdict_clean = verdict.lower()
    if verdict_clean == "malicious":
        print("\n" + Back.RED + Fore.WHITE + Style.BRIGHT + "VERDICT : MALICIOUS ".center(70) + Style.RESET_ALL)
    elif verdict_clean == "no_threat":
        print("\n" + Back.GREEN + Fore.BLACK  + "VERDICT : CLEAN ".center(70) + Style.RESET_ALL)
    elif verdict_clean == "unknown":
        print("\n" + Back.WHITE + Fore.BLACK  + "VERDICT : UNKNOWN ".center(70) + Style.RESET_ALL)
    else:
        print("\n" + Back.YELLOW + Fore.BLACK + f"VERDICT : {verdict.upper()} ".center(70) + Style.RESET_ALL)
    print()

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Search for SHA256 in malware database")
    parser.add_argument("sha256", nargs="+", help="SHA256 hash(es) to search for")
    args = parser.parse_args()
    
    print(ASCII_ART)
    print_header(1)

    for hash256 in args.sha256:
        if not is_valid_sha256(hash256):
            print(f"{Fore.RED}[✗] Invalid SHA256 hash : {hash256}\n")
        else:
            print(f"[❯] Searching : {hash256}\n")
    
    print_header(2)
    malwarebazaar_search.search_malbazaar(hash256)

    print("\n")
    print_header(3)
    filescanio_search.search_filescan(hash256)

if __name__ == "__main__":
    main()
