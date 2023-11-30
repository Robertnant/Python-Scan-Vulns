import os
import requests
import json
import zipfile
import sqlite3
from urllib.parse import urljoin

# Create a folder to store the ZIP files
download_folder = 'nvd_cve_zip_files'
os.makedirs(download_folder, exist_ok=True)

# Define the base URL for NVD CVE data
base_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/'

# Define the range of years you're interested in
start_year = 2018
end_year = 2023

# Download and extract NVD CVE ZIP files for each year
for year in range(start_year, end_year + 1):
    zip_file_name = f'nvdcve-1.1-{year}.json.zip'
    zip_file_url = urljoin(base_url, zip_file_name)
    zip_file_path = os.path.join(download_folder, zip_file_name)
    
    response = requests.get(zip_file_url)
    with open(zip_file_path, 'wb') as zip_file:
        zip_file.write(response.content)

    print(f'Downloaded: {zip_file_name}')

    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(download_folder)

    print(f'Extracted: {zip_file_name}')

# Initialize SQLite database
conn = sqlite3.connect('vulnerabilities_all_years.db')
cursor = conn.cursor()

# Create a table to store vulnerability data
cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        description TEXT,
        severity REAL,
        affected_software TEXT,
        references_data TEXT
    )
''')

# Process and store data from all extracted files
for year in range(start_year, end_year + 1):
    json_file_name = f'nvdcve-1.1-{year}.json'
    json_file_path = os.path.join(download_folder, json_file_name)

    with open(json_file_path) as file:
        nvd_data = json.load(file)

    print(f'Processing: {json_file_name}')

    for cve_item in nvd_data['CVE_Items']:
        cve_id = cve_item['cve']['CVE_data_meta']['ID']
        description = cve_item['cve']['description']['description_data'][0]['value']

        if 'baseMetricV3' in cve_item['impact']:
            severity = cve_item['impact']['baseMetricV3']['cvssV3']['baseScore']
        elif 'baseMetricV2' in cve_item['impact']:
            severity = cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
        else:
            severity = None

        affected_software = json.dumps([
            {
                'vendor': cpe_match.get('cpe23Uri', '').split(':')[3],
                'product': cpe_match.get('cpe23Uri', '').split(':')[4],
                'version': cpe_match.get('cpe23Uri', '').split(':')[5],
            }
            for node in cve_item.get('configurations', {}).get('nodes', [])
            if 'cpe_match' in node
            for cpe_match in node['cpe_match']
        ])

        references_data = json.dumps([
            {
                'url': reference_data.get('url', ''),
                'name': reference_data.get('name', ''),
                'source': reference_data.get('refsource', ''),
            }
            for reference_data in cve_item.get('cve', {}).get('references', {}).get('reference_data', [])
        ])

        cursor.execute('''
            INSERT INTO vulnerabilities (cve_id, description, severity, affected_software, references_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (cve_id, description, severity, affected_software, references_data))

    print(f'Stored in database: {json_file_name}')

conn.commit()
conn.close()

# Remove downloaded ZIP files
for year in range(start_year, end_year + 1):
    zip_file_name = f'nvdcve-1.1-{year}.json.zip'
    zip_file_path = os.path.join(download_folder, zip_file_name)
    os.remove(zip_file_path)

print('Data from all years has been stored in the SQLite database.')
