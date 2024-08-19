import os
import requests
import time
import json

with open('.key.txt', 'r') as key_file:
    API_KEY = key_file.read().strip()

SCAN_URL = 'https://www.virustotal.com/api/v3/files'
REPORT_URL = 'https://www.virustotal.com/api/v3/analyses/'

HEADERS = {
    'x-apikey': API_KEY
}

def upload_file(file_path):
    with open(file_path, 'rb') as file:
        response = requests.post(SCAN_URL, headers=HEADERS, files={'file': file})
    if response.status_code == 200:
        analysis_id = response.json().get('data', {}).get('id')
        return analysis_id
    else:
        print(f"klaida įkeliant failą {file_path}: {response.status_code} {response.text}")
        return None

def get_report(analysis_id):
    response = requests.get(f"{REPORT_URL}{analysis_id}", headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Serverio klaida {analysis_id}: {response.status_code} {response.text}")
        return None

def select_files_to_scan(files_directory):
    files = os.listdir(files_directory)
    files = [f for f in files if os.path.isfile(os.path.join(files_directory, f))]
    
    if not files:
        print("Tuščias aplankalas.")
        return []

    print("Pasirinkite failo skaičių kurį norite patikrinti: ")
    for i, file in enumerate(files):
        print(f"{i + 1}. {file}")
    
    selected_indices = input("Įveskite eilės numerį: ").split(',')
    selected_files = []

    try:
        selected_files = [files[int(index.strip()) - 1] for index in selected_indices]
    except (IndexError, ValueError):
        print("Blogas pasirinkimas. Turi būti skaičius esantis saraše")
        return select_files_to_scan(files_directory)

    return selected_files

def scan_selected_files(directory_path, selected_files, output_file):
    results = []
    malicious_found = False

    for file_name in selected_files:
        file_path = os.path.join(directory_path, file_name)
        print(f"Skanuojamas failas: {file_path}")
        analysis_id = upload_file(file_path)
        if analysis_id:
            for i in range(45, 0, -1):
                print(f"Laukiama kol bus baigta failo analizė... Liko {i} sekundės ", end='\r')
                time.sleep(1)
            print("Laukiama kol bus baigta failo analizė... Baigta!               ")  
            report = get_report(analysis_id)
            if report:
                data = report.get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('stats', {})
                result = {
                    'file': file_name,
                    'status': 'Malicious' if stats.get('malicious', 0) > 0 else 'Clean',
                    'report': report
                }
                if stats.get('malicious', 0) > 0:
                    malicious_found = True
                results.append(result)

    final_output = {
        'results': results,
        'summary': {
            'all_clean': not malicious_found,
            'total_files': len(results),
            'malicious_files': len([r for r in results if r['status'] == 'Malicious']),
            'clean_files': len([r for r in results if r['status'] == 'Clean'])
        }
    }

    with open(output_file, 'w') as f:
        json.dump(final_output, f, indent=4)

    if malicious_found:
        print("\033[91mAptikti kenksmingi failai, patikrinkite ataskaita!\033[0m")
    else:
        print("\033[92mKenksmingų failų nerasta.\033[0m")

    
    return malicious_found

if __name__ == "__main__":
    while True:
        directory = os.path.join(os.getcwd(), 'files')
        output_file = 'virus_total_scan_results.json'
        
        selected_files = select_files_to_scan(directory)
        if not selected_files:
            break
        
        scan_selected_files(directory, selected_files, output_file)

        repeat = input("Ar norite skanuoti kitą failą? (taip/ne): ").strip().lower()
        if repeat != 'taip':
            print("Programos pabaiga.")
            break
