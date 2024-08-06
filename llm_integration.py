import pandas as pd
from transformers import pipeline

from determine_the_vendor import determine_vendor

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
    "Withings": ["Camera", "Scale", "Sleep monitor"]
}

df = pd.read_csv('enriched_data2.csv', encoding='ISO-8859-1')
classifier = pipeline("zero-shot-classification", model="FacebookAI/roberta-large-mnli")
vendor = determine_vendor()
functions = vendors_functions[vendor]
sequence_to_classify = "This is an IoT device with the follwoing characteristics: Enriched Hostname {}," \
                       "  Domains {}. Hostname is the most important part of this".format(df.iloc[0, 3], df.iloc[0, 2], df.iloc[0, 3], df.iloc[0, 1])
t = classifier(sequence_to_classify, functions)
print(t['labels'][0])
print(t['scores'][0])