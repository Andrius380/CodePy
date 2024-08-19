import os
import json
from typing import List
from virus_total import select_files_to_scan, scan_selected_files

def main():
    with open('.key.txt', 'r') as key_file:
        API_KEY = key_file.read().strip()

    while True:
        directory = os.path.join(os.getcwd(), 'files')
        output_file = 'virus_total_scan_results.json'
        
        selected_files = select_files_to_scan()
        if not selected_files:
            break
        
        scan_selected_files(directory, selected_files, output_file, API_KEY)

        repeat = input("Ar norite skanuoti kitą failą? (taip/ne): ").strip().lower()
        if repeat != 'taip':
            print("Programos pabaiga.")
            break

if __name__ == "__main__":
    main()