import csv
import random
import re
import time
import requests
import bs4


def clean_string(text):
    cleaned_text = re.sub(r'[\u200e\u200f\u00a0\u202a-\u202e\u2066-\u2069\u200c\u200d\ufeff\u2028\u2029\u2192]', '', text) # to remove special Unicode characters
    return cleaned_text

def process_row(row):
    domains_list = []
    result_domains = ''
    result_mac = ''
    mac_organizations_list = []
    device_name = row[0]
    hostname = row[4]
    host = ''
    domains = row[1].split(';')
    if len(domains) < 16:
        mac_organizations = row[3].split(';')
        if len(domains) != 0:
            for d in domains:
                if "pool.ntp.org" in d:
                    domains_list.append([d])
                else:
                    domains_list.append(google_request_function(d.replace("_", " ")))
        if mac_organizations != 0:
            for m in mac_organizations:
                mac_organizations_list.append(google_request_function(m))
        if (all([True for l in domains_list if len(l) == 0])):
            if len(domains_list) > 1:
                flattened_domains = [item for sublist in domains_list for item in sublist]
                result_domains = clean_string(';'.join(flattened_domains))
            else:
                result_domains = domains_list[0]
        else:
                result_domains = ''

        if (all([True for l in mac_organizations_list if len(l) == 0])):
            if len(mac_organizations_list) > 1:
                flattened_mac = [item for sublist in mac_organizations_list for item in sublist]
                result_mac = clean_string(';'.join(flattened_mac))
            else:
                result_mac = mac_organizations_list[0]
        else:
            result_mac = ''
        host = google_request_function(hostname)
    return {
        "PCAP File": device_name,
        "Domains": result_domains,
        "MAC Organizations": result_mac,
        "Host": host
    }
def google_request_function(temp_text):
    cell_data = []
    headers = {'User-agent':
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 "
    "Safari/537.36" }
    html = requests.get('https://www.google.com/search?hl=en&q=' + temp_text, headers=headers)
    soup = bs4.BeautifulSoup(html.text, 'html.parser')
    all_headers = soup.find_all('h3', class_='LC20lb MBeuO DKV0Md')
    first_sentences = soup.find_all('div', class_='VwiC3b yXK7lf lVm3ye r025kc hJNv6b Hdw6tb')
    for div, sen in zip(all_headers[:7], first_sentences[:7]):
        header = div.get_text(strip=True)
        sentence = sen.get_text(strip=True)
        cell_data.append(header + " " + sentence)
    time.sleep(random.randrange(7, 14))
    return cell_data

def write_results_to_csv(file_path, results):
    with open(file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=["PCAP File",
                                                  "Domains",
                                                  "MAC Organizations",
                                                  "Host"
                                                  ])
        writer.writeheader()
        writer.writerows(results)


with open('file.csv', newline='', encoding='ISO-8859-1') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    results = []
    for _ in range(1):
        next(csvreader)
    for row in csvreader:
        results.append(process_row(row))
        write_results_to_csv('enriched_data2.csv', results)


