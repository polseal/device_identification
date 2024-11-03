import csv
import random
import re
import sys
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
def is_captcha_present(soup):
    captcha_div = soup.find('div', {'class': 'g-recaptcha'})
    unusual_traffic_message = soup.find(text="unusual traffic")
    return captcha_div, unusual_traffic_message

def google_request_function(temp_text):
    cell_data = []
    max_retries = 15
    base_delay = 1800
    factor = 2
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/537.36 (KHTML, like Gecko) Version/16.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.46"
    ]
    soup = get_data_from_google(temp_text, user_agents)
    # Check for CAPTCHA page
    captcha_div, unusual_traffic_message = is_captcha_present(soup)

    if captcha_div or unusual_traffic_message:
        for attempt in range(max_retries):
            delay = base_delay * factor + random.uniform(0, 300)
            print(f"CAPTCHA detected. Attempt {attempt + 1} of {max_retries}. Retrying after delay...{delay}")
            time.sleep(delay)
            soup = get_data_from_google(temp_text, user_agents)
            captcha_div, unusual_traffic_message = is_captcha_present(soup)
            if not (captcha_div or unusual_traffic_message):
                return soup
        print("Maximum retries reached. Stopping the script.")
        sys.exit()

    all_headers = soup.find_all('h3', class_='LC20lb MBeuO DKV0Md')
    first_sentences = soup.find_all('div', class_='VwiC3b yXK7lf lVm3ye r025kc hJNv6b Hdw6tb')
    for div, sen in zip(all_headers[:7], first_sentences[:7]):
        header = div.get_text(strip=True)
        sentence = sen.get_text(strip=True)
        cell_data.append(header + " " + sentence)
    lambda_param = 0.08
    time.sleep(random.expovariate(lambda_param))
    return cell_data


def get_data_from_google(temp_text, user_agents):
    headers = {'User-agent': random.choice(user_agents)}
    html = requests.get('https://www.google.com/search?hl=en&q=' + temp_text, headers=headers)
    soup = bs4.BeautifulSoup(html.text, 'html.parser')
    return soup


def write_results_to_csv(file_path, results):
    with open(file_path, mode='a', newline='', encoding='utf-8') as file: #code updated to mode=a to append the file
        writer = csv.DictWriter(file, fieldnames=["PCAP File",
                                                  "Domains",
                                                  "MAC Organizations",
                                                  "Host"
                                                  ])
        if file.tell() == 0:  # This checks if the file is empty or new
            writer.writeheader()
        writer.writerows(results)


with open('file.csv', newline='', encoding='ISO-8859-1') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')

    for _ in range(1):
        next(csvreader)
    for row in csvreader:
        results = []
        results.append(process_row(row))
        write_results_to_csv('enriched_data2.csv', results)


