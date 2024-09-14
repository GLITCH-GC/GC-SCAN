import whois
import requests
from colorama import init, Fore, Style


init(autoreset=True)


VIRUSTOTAL_API_KEY = 'YOUR_API'
ABUSEIPDB_API_KEY = 'YOUR_API'

def print_logo():
    logo = f"""
{Fore.CYAN}{Style.BRIGHT}
   _____   _____    _____                    
  / ____| / ____|  / ____|                   
 | |  __ | |  __  | |      ___   ___  ___    
 | | |_ || | |_ | | |     / _ \ / __|/ _ \   
 | |__| || |__| | | |____| (_) | (__|  __/   
  \_____| \_____|  \_____|\___/ \___|\___|   
{Fore.YELLOW}               GC-SCAN
    """
    print(logo)

# 1. WHOIS Lookup
def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return f"Error fetching WHOIS data: {e}"

# 2. IP Reputation Check (AbuseIPDB)
def ip_reputation_check(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    return response.json()

# 3. Threat Intelligence Automation (VirusTotal using requests)
def threat_intel_check(domain):
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'domain': domain}
    response = requests.get(url, params=params)
    return response.json()


def save_to_file(data, filename="threat_intelligence_report.txt"):
    with open(filename, 'w') as file:
        file.write(data)
    print(f"{Fore.GREEN}The report has been saved to {filename}")


def main():
    print_logo()
    print(f"{Fore.GREEN}Welcome to the {Fore.YELLOW}GC-SCAN {Fore.GREEN}Tool")
    while True:
        print(f"\n{Fore.BLUE}Options:")
        print(f"{Fore.CYAN}1. {Fore.WHITE}WHOIS Lookup")
        print(f"{Fore.CYAN}2. {Fore.WHITE}IP Reputation Check")
        print(f"{Fore.CYAN}3. {Fore.WHITE}Threat Intelligence Check")
        print(f"{Fore.CYAN}4. {Fore.WHITE}Exit")

        choice = input(f"\n{Fore.GREEN}Enter your choice (1-4): {Fore.RESET}")

        if choice == '1':
            domain = input(f"{Fore.GREEN}Enter a domain for WHOIS lookup: {Fore.RESET}")
            whois_data = whois_lookup(domain)
            print(f"\n{Fore.YELLOW}WHOIS Information:")
            print(whois_data)

        elif choice == '2':
            ip = input(f"{Fore.GREEN}Enter an IP for reputation check: {Fore.RESET}")
            ip_reputation = ip_reputation_check(ip)
            print(f"\n{Fore.YELLOW}IP Reputation Report:")
            print(ip_reputation)

        elif choice == '3':
            domain = input(f"{Fore.GREEN}Enter a domain for threat intelligence check: {Fore.RESET}")
            threat_intel = threat_intel_check(domain)
            print(f"\n{Fore.YELLOW}Threat Intelligence Report:")
            print(threat_intel)

            
            save_option = input(f"{Fore.CYAN}Would you like to save the report to a file? (yes/no): {Fore.RESET}").strip().lower()
            if save_option == 'yes':
                file_name = input(f"{Fore.GREEN}Enter the file name (default: threat_intelligence_report.txt): {Fore.RESET}").strip()
                if not file_name:
                    file_name = "threat_intelligence_report.txt"
                save_to_file(str(threat_intel), file_name)

        elif choice == '4':
            print(f"{Fore.GREEN}Exiting the tool. Goodbye!")
            break

        else:
            print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()

