import csv

import pandas as pd
from transformers import pipeline

from determine_the_vendor import determine_vendor, get_vendor_by_device_name

vendors_functions = {
    "Amazon": ["Home Assistants and Speakers", "Streaming Devices"],
    "Apple": ["Computers", "Smartphone", "Streaming Devices"],
    "Awair": ["Air Monitor"],
    "Belkin": ["Bridge", "Motion Sensors", "Switch"],
    "Blink": ["Camera"],
    "Bosiwo": ["Camera"],
    "Chamberlain": ["Appliances"],
    "D-Link": ["Camera", "Plugs", "Water sensor"],
    "eQ-3": ["Gateway", "Switch"],
    "Google": ["Home Assistants and Speakers", "Streaming Devices"],
    "Harman Kardon": ["Home Assistants and Speakers"],
    "Honeywell": ["Appliances"],
    "HP": ["Printers"],
    "iHome": ["Plugs"],
    "Insteon": ["Camera", "Hub"],
    "Invoxia": ["Home Assistants and Speakers"],
    "iRobot": ["Appliances"],
    "Laptop": ["Computers"],
    "LIFX": ["Bulb"],
    "MagicHome": ["Light Bulbs and Lighting Control"],
    "Nest": ["Camera"],
    "Nest (Google)": ["Appliances"],
    "Netatmo": ["Camera"],
    "Osram": ["Hub", "Light Bulbs and Lighting Control"],
    "Philips": ["Bridge", "Bulb", "Switch"],
    "Piper": ["Camera"],
    "Pix-Star": ["Appliances"],
    "Ring": ["Camera"],
    "Samsung": ["Camera", "Hub", "Hubs and Bridges", "Tablets"],
    "Sengled": ["Hub"],
    "Smarter": ["Appliances", "Hubs and Bridges"],
    "Smartphone": ["Smartphone"],
    "TP-Link": ["Bulb", "Plugs"],
    "Withings": ["Camera", "Scale", "Sleep monitor"],
    "Canary": ["Camera"],
    "August": ["Doorbell", "Smart Lock"],
    "Carematrix": ["Blood Pressure Monitor", "Weight Scale", "Pulse Oximeter", "Glucometer"]
}

df = pd.read_csv('enriched_data2.csv', encoding='ISO-8859-1')
classifier = pipeline("zero-shot-classification", model="FacebookAI/roberta-large-mnli")

vendor = determine_vendor()
vendor_actual_df = pd.read_csv('vendor_actual.csv')
results = []
for index, row in df.iterrows():
    try:
        vendor = get_vendor_by_device_name(row[0], vendor_actual_df)
        functions = vendors_functions[vendor]
        sequence_to_classify = ("This is an IoT device of the vendor {} with the following characteristics: "
                                "Enriched Hostname {}, Domains {}. Hostname is the most important part of this."
                                ).format(vendor, row[3], row[1])

        t = classifier(sequence_to_classify, functions)

        results.append({
            'Name': row[0],
            'Vendor': vendor,
            'Label': t['labels'][0],
            'Score': t['scores'][0]
        })
    except Exception as e:
        print(e)

results_df = pd.DataFrame(results)

results_df.to_csv('results.csv', index=False)