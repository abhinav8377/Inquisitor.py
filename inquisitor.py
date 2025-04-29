import argparse
import requests
import whois
import socket
import dns.resolver
import re

# ==============================
#           BANNER
# ==============================
def show_banner():
    print(r"""
  ___           _           _             
 |_ _|_ __  ___| |_   _  __| |_ __  _   _ 
  | || '_ \/ __| | | | |/ _` | '_ \| | | |
  | || | | \__ \ | |_| | (_| | | | | |_| |
 |___|_| |_|___/_|\__,_|\__,_|_| |_|\__, |
                                    |___/ 
       OSINT Framework - by Abhinav
    """)

# ==============================
#       USERNAME CHECK
# ==============================
def username_lookup(username):
    print(f"\n[+] Checking username across platforms: {username}")
    sites = [
        f"https://github.com/{username}",
        f"https://www.reddit.com/user/{username}",
        f"https://twitter.com/{username}",
        f"https://www.instagram.com/{username}/",
        f"https://www.tiktok.com/@{username}"
    ]
    for site in sites:
        try:
            r = requests.get(site, timeout=5)
            if r.status_code == 200:
                print(f"[FOUND] {site}")
            else:
                print(f"[NOT FOUND] {site}")
        except:
            print(f"[ERROR] {site}")

# ==============================
#         DOMAIN LOOKUP
# ==============================
def domain_lookup(domain):
    print(f"\n[+] DOMAIN LOOKUP: {domain}")
    try:
        w = whois.whois(domain)
        print("[WHOIS INFO]")
        print(w)
    except Exception as e:
        print(f"[!] WHOIS Error: {e}")

    print("\n[+] DNS Records:")
    try:
        for rdata in dns.resolver.resolve(domain, 'A'):
            print(f"A Record: {rdata}")
    except:
        print("[-] No A record found")

    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip}")
    except:
        print("[-] Could not resolve domain")

# ==============================
#         EMAIL INTEL
# ==============================
def email_lookup(email):
    print(f"\n[+] EMAIL INTELLIGENCE: {email}")
    if re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print("[+] Email format appears valid")
    else:
        print("[!] Invalid email format")
        return

    print("[+] (Stub) Breach check would go here with HaveIBeenPwned API")

# ==============================
#         IP LOOKUP
# ==============================
def ip_lookup(ip):
    print(f"\n[+] IP LOOKUP: {ip}")
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}")
        data = res.json()
        for k, v in data.items():
            print(f"{k}: {v}")
    except:
        print("[!] Failed to retrieve IP info")

# ==============================
#     SOCIAL MEDIA SCRAPER
# ==============================
def social_lookup(username):
    print(f"\n[+] SOCIAL MEDIA OSINT for: {username}")
    print(f"[*] Twitter Profile: https://twitter.com/{username}")
    print(f"[*] Instagram Profile: https://instagram.com/{username}")
    print(f"[*] LinkedIn Profile (guess): https://linkedin.com/in/{username}")
    print("🧠 (Note: Real scraping needs login/API access)")

# ==============================
#         ARGPARSE CLI
# ==============================
def main():
    show_banner()
    parser = argparse.ArgumentParser(description="Inquisitor - Combined OSINT Toolkit")

    parser.add_argument("--username", help="Check username on multiple sites")
    parser.add_argument("--domain", help="Gather info about a domain")
    parser.add_argument("--email", help="Investigate email address")
    parser.add_argument("--ip", help="Lookup IP address")
    parser.add_argument("--social", help="Scrape public social links")

    args = parser.parse_args()

    if args.username:
        username_lookup(args.username)
    if args.domain:
        domain_lookup(args.domain)
    if args.email:
        email_lookup(args.email)
    if args.ip:
        ip_lookup(args.ip)
    if args.social:
        social_lookup(args.social)

if __name__ == "__main__":
    main()
