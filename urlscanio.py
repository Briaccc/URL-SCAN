import tkinter as tk
import requests
import json
from PIL import Image, ImageTk
import time
import whois
import socket


# API Key et URL de l'API
api_key = 'API KEY'
api_url = 'https://urlscan.io/api/v1/scan/'

headers = {
    'API-Key': api_key,
    'Content-Type': 'application/json',
}


# Fonction pour récupérer les détails complets de l'analyse
def get_analysis_details(scan_id):
    url = f'https://urlscan.io/api/v1/result/{scan_id}/'
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

# Fonction pour récupérer le verdict
def extract_verdict(analysis_details):
    if analysis_details:
        verdict = analysis_details['verdicts']['overall']
        return "L'URL est considérée comme malveillante." if verdict['malicious'] else "L'URL est considérée comme sûre."
    else:
        return "Impossible de récupérer les détails complets de l'analyse."

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Impossible de résoudre l'adresse IP pour ce domaine."


def get_domain_creation_date(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info.creation_date
    except whois.parser.PywhoisError:
        return "Impossible d'obtenir la date de création pour ce domaine."



# Fonction pour soumettre l'URL et afficher les résultats
def submit_url():
    url_to_scan = entry.get()
    data = {'url': url_to_scan}
    domain = url_to_scan.split('//')[-1].split('/')[0]
    ip_address = get_ip_address(domain)
    ip_label.config(text=f"Adresse IP du site : {ip_address}")
    
    response = requests.post(api_url, headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        result = response.json()
        scan_id = result['uuid']
        result_url = f'https://urlscan.io/result/{scan_id}/'
        screenshot_url = f'https://urlscan.io/screenshots/{scan_id}.png'

        result_label.config(text=f"URL de résultat : {result_url}")

        # Pause de 10 secondes
        time.sleep(10)

        # Charger et afficher l'image
        img = Image.open(requests.get(screenshot_url, stream=True).raw)
        img = img.resize((300, 200))  # Redimensionner l'image si nécessaire

        img = ImageTk.PhotoImage(img)
        screenshot_image.config(image=img)
        screenshot_image.image = img  # Gardez une référence

        # Récupérer les détails complets de l'analyse
        analysis_details = get_analysis_details(scan_id)

        # Afficher le verdict
        verdict = extract_verdict(analysis_details)
        verdict_label.config(text=verdict)

        # Récupérer les détails complets de l'analyse
        analysis_details = get_analysis_details(scan_id)


        # Obtenir le domaine à partir de l'URL analysée
        url_to_scan = entry.get()
        domain = url_to_scan.split('//')[-1].split('/')[0]

        # Obtenir la date de création du domaine
        creation_date = get_domain_creation_date(domain)
        creation_date_label.config(text=f"Date de création du domaine : {creation_date}")

    else:
        result_label.config(text="Erreur lors de la soumission de l'URL")

                # Appel de copy_to_clipboard en lui passant screenshot_url

# Interface graphique
root = tk.Tk()
root.title("Analyse d'URL")

label = tk.Label(root, text="Entrez l'URL à analyser :")
label.pack()

entry = tk.Entry(root)
entry.pack()

submit_button = tk.Button(root, text="Analyser", command=submit_url)
submit_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

screenshot_label = tk.Label(root, text="")
screenshot_label.pack()

screenshot_image = tk.Label(root)
screenshot_image.pack()

verdict_label = tk.Label(root, text="")
verdict_label.pack()

additional_info_label = tk.Label(root, text="")
additional_info_label.pack()

ip_label = tk.Label(root, text="")
ip_label.pack()

creation_date_label = tk.Label(root, text="")
creation_date_label.pack()


root.mainloop()
