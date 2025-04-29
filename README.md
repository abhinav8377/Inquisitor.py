# Inquisitor.py - OSINT Recon Tool
Inquisitor is a modular, command-line Open Source Intelligence (OSINT) tool developed in Python. It automates the process of information gathering across domains, usernames, emails, IP addresses, and social profiles

# Features
🔎 Username Enumeration – Check usernames across major social platforms
🌐 Domain Reconnaissance – WHOIS, DNS, IP resolution, and more
📧 Email Validation – Regex-based format checking with breach-check stub
🌍 IP Geolocation – ASN, ISP, country, city data via IP-API
📱 Social Media Lookup – Quick-view links to public profiles

# Help - Output
![{12BD2CD3-CCE1-48F7-8CA6-A444C65C389F}](https://github.com/user-attachments/assets/70359eec-0aa0-4c26-aaf3-6bf66666d949)

# Prerequisites
Before using Inquisitor, ensure the following are installed:
-->  Python 3.8 or above
-->  specially for linux, ubuntu

# Install Dependencies
    pip install requests whois dnspython

# Usage🚀
    python inquisitor.py [--username USER] [--domain DOMAIN] [--email EMAIL] [--ip IP] [--social USER]

# Examples
    python3 inquisitor.py --domain github.com --ip 140.82.114.3
