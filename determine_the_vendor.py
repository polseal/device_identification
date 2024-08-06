import csv
from collections import Counter
import pandas as pd



def read_vendors_from_csv(file_path):
    vendors = []
    with open(file_path, mode='r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            vendors.append(row["Vendors"])
    return vendors


def determine_vendor():
    with open('enriched_data2.csv', newline='', encoding='ISO-8859-1') as file:
        reader = csv.reader(file)
        data = list(reader)

    enriched = pd.DataFrame(data, columns=data[0])

    base = pd.read_csv('file.csv', encoding='ISO-8859-1')

    merged_df = pd.merge(enriched, base, on='PCAP File', how='inner')

    vendors = read_vendors_from_csv('vendors.csv')
    for index, row in merged_df.iterrows():
        try:
            device_name = row[0]
            vendor_counts = Counter()
            l = len(row)
            for vendor in vendors:
                for i in range(1, l):
                    if pd.notna(row[i]):
                        vendor_counts[vendor] = vendor_counts[vendor] + row[i].lower().count(vendor.lower())
            most_common_vendor = '' if all(value == 0 for value in vendor_counts.values()) else \
            vendor_counts.most_common(1)[0]
            print(device_name, " ", most_common_vendor)
            return most_common_vendor[0]
        except Exception as e:
            print(f"Error processing row {index}: {e}")
            continue




