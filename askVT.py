import sys
import csv
import os
from dotenv import load_dotenv
import requests

from tqdm import tqdm

from concurrent.futures import ThreadPoolExecutor, as_completed

class AskVT:

    api_url = ""
    api_call_headers = {}

    def init(self):
        load_dotenv(dotenv_path="envar.env", override=True)
        # SHA256: 64 hex numbers (4 bits * 64 = 256 bits)
        self.api_url = "https://www.virustotal.com/api/v3/files/"
        self.api_call_headers = {"accept": "application/json", "x-apikey": os.getenv('VT_API_KEY')}
    
    def process_line(self, row):
        n, m, desc = self.get_VT_freport(row[2])
        if n != 0:
            return f"Found!: {row[0]}, {row[1]}, ({n}/{m}), \n{desc}"
        else:
            return ""

    def process_csv_parallel(self, filename):
        with open(filename, mode='r', encoding='CP949') as file:
            csv_reader = csv.reader(file)

            rows = list(csv_reader)
            total_lines = len(rows) - 1  # since we don't process the header line
            
            with ThreadPoolExecutor() as executor:
                futures = {executor.submit(self.process_line, row): row for row in rows[1:]} # rows[1:] to skip the header
                
                with tqdm(total=total_lines, desc="Processing CSV") as pbar:
                    for future in as_completed(futures):
                        result = future.result()
                        # if result != "":
                        #     print(result)
                        print(result)
                        pbar.update(1)

    def start(self, filename):
        self.process_csv_parallel(filename)

    def get_VT_freport(self, file_hash):
        n = 0
        m = 0
        string_list = []

        resp = requests.get(self.api_url+file_hash, headers=self.api_call_headers)
        resp_json = resp.json()

        try:
            #string_list.append(f"Last Analysis\n")
            malicious_cnt = int(resp_json['data']['attributes']['last_analysis_stats']['malicious'])
            suspicious_cnt = int(resp_json['data']['attributes']['last_analysis_stats']['suspicious'])
            undetected_cnt = int(resp_json['data']['attributes']['last_analysis_stats']['undetected'])
            harmless_cnt = int(resp_json['data']['attributes']['last_analysis_stats']['harmless'])

            n = malicious_cnt + suspicious_cnt
            m = malicious_cnt + suspicious_cnt + undetected_cnt + harmless_cnt
        except KeyError as kerr:
            n = 0
            m = 0
            pass
        except ValueError as verr:
            n = 0
            m = 0
            pass

        try:
            #string_list.append(f"Trusted verdict\n")
            string_list.append(f"File name: {resp_json['data']['attributes']['trusted_verdict']['filename']}\n")
            string_list.append(f"Verdicted as: {resp_json['data']['attributes']['trusted_verdict']['verdict']}\n")
            string_list.append(f"Verdicted by: {resp_json['data']['attributes']['trusted_verdict']['organization']}\n")
        except KeyError as kerr:
            pass
        except ValueError as verr:
            pass

        try:
            #string_list.append(f"Exiftool\n")
            string_list.append(f"InternalName: {resp_json['data']['attributes']['exiftool']['InternalName']}\n")
            string_list.append(f"FileDescription: {resp_json['data']['attributes']['exiftool']['FileDescription']}\n")
            string_list.append(f"Characterset: {resp_json['data']['attributes']['exiftool']['CharacterSet']}\n")
            string_list.append(f"OriginalFileName: {resp_json['data']['attributes']['exiftool']['OriginalFileName']}\n")
        except KeyError as kerr:
            pass
        except ValueError as verr:
            pass

        return (n, m, string_list)
    

#############################
# main
#############################

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: Filename must be provided as a command line argument.")
        sys.exit(1)

    filename = sys.argv[1]
    a = AskVT()
    a.init()
    a.start(filename)
    