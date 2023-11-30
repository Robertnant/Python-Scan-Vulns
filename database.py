import os
import requests
import json
import zipfile
import sqlite3
from urllib.parse import urljoin
from datetime import datetime, timedelta

OUTDATED_CVE_TIMEDELTA = 7
VULNERABILITIES_DATABASE_PATH = 'vulnerabilities_all_years.db'

def download_cve():
    # Create a folder to store the ZIP files
    download_folder = 'nvd_cve_zip_files'
    os.makedirs(download_folder, exist_ok=True)

    # Define the base URL for NVD CVE data
    base_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/'

    # Define the range of years you're interested in
    start_year = 2018
    end_year = 2023

    # Download and extract NVD CVE ZIP files for each year
    if not should_download_files(download_folder, start_year, end_year):
        print('Database already exists and is up to date. The existing database will be used.')
        return
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
    conn = sqlite3.connect(VULNERABILITIES_DATABASE_PATH)
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
    # TODO: Download database only if files date from long ago.
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

            affected_software = []
            configurations = cve_item.get('configurations', {}).get('nodes', [])
            for node in configurations:
                if 'cpe_match' in node:
                    for cpe_match in node['cpe_match']:
                        # Check if the entry already exists in affected_software
                        entry_exists = any(
                            entry['vendor'] == cpe_match.get('cpe23Uri', '').split(':')[3] and
                            entry['product'] == cpe_match.get('cpe23Uri', '').split(':')[4] and
                            entry['version'] == cpe_match.get('cpe23Uri', '').split(':')[5]
                            for entry in affected_software
                        )

                        # Add the entry only if it doesn't already exist
                        if not entry_exists:
                            affected_software.append({
                                'vendor': cpe_match.get('cpe23Uri', '').split(':')[3],
                                'product': cpe_match.get('cpe23Uri', '').split(':')[4],
                                'version': cpe_match.get('cpe23Uri', '').split(':')[5],
                                # Add more version-related fields as needed
                            })
            affected_software = json.dumps(affected_software)
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


def fetch_vulnerabilities(cursor, service_name, version):
    cursor.execute('''
        SELECT cve_id, description, severity, references_data
        FROM vulnerabilities
        WHERE JSON_ARRAY_LENGTH(affected_software) > 0 AND (
            EXISTS (
                SELECT 1
                FROM json_each(affected_software)
                WHERE 
                    json_extract(value, '$.product') = ? AND
                    json_extract(value, '$.version') = ?
            )
        )
    ''', (service_name, version))
    return cursor.fetchall()


def check_vulnerabilities():
    # Update CVE if needed.
    download_cve()

    # Read the file containing exposed devices' information
    with open('all_exposed_devices.json') as file:
        exposed_devices_data = json.load(file)

    # Connect to the SQLite database
    conn = sqlite3.connect(VULNERABILITIES_DATABASE_PATH)
    cursor = conn.cursor()

    # List to store vulnerabilities information
    vulnerabilities_info = []

    # Iterate through each exposed device
    for exposed_device in exposed_devices_data.get('all_exposed_devices', []):
        ip_address = exposed_device.get('ip_address', '')
        
        # Iterate through services of each exposed device
        for service in exposed_device.get('services', []):
            service_name = service.get('name', '')
            service_version = service.get('version', '')

            # Fetch vulnerabilities for the service name and version
            vulnerabilities = fetch_vulnerabilities(cursor, service_name, service_version)

            # Append vulnerabilities information to the list
            for cve_id, description, severity, references_data in vulnerabilities:
                references = json.loads(references_data)

                # Extract recommendations from references
                recommendations = [
                    ref.get('url', '') for ref in references
                ]
                vulnerabilities_info.append({
                    'ip_address': ip_address,
                    'cve_id': cve_id,
                    'description': description,
                    'severity': severity,
                    'recommendations': recommendations,
                })

    # Close the connection to the database
    conn.close()

    print(vulnerabilities_info)
    return vulnerabilities_info

def retrieve_vulnerabilities(database_path, limit=10):
    # Connect to the SQLite database
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    # Fetch vulnerabilities from the database
    cursor.execute(f'SELECT * FROM vulnerabilities LIMIT {limit}')
    results = cursor.fetchall()

    # Process and print retrieved vulnerabilities
    retrieved_vulnerabilities = []
    for result in results:
        vulnerability = {
            'cve_id': result[1],
            'description': result[2],
            'severity': result[3],
            'affected_software': json.loads(result[4]),
            'references_data': json.loads(result[5]),
        }
        retrieved_vulnerabilities.append(vulnerability)

    # Close the connection
    conn.close()

    return retrieved_vulnerabilities

def should_download_files(download_folder, start_year, end_year):
    # Check if NVD CVE files for the given years are already present
    for year in range(start_year, end_year + 1):
        json_file_name = f'nvdcve-1.1-{year}.json'
        json_file_path = os.path.join(download_folder, json_file_name)
        if not os.path.isfile(json_file_path):
            return True

        # Check if the existing file is older than one week
        one_week_ago = datetime.now() - timedelta(days=OUTDATED_CVE_TIMEDELTA)
        file_modified_time = datetime.fromtimestamp(os.path.getmtime(json_file_path))
        if file_modified_time < one_week_ago:
            return True

    return False


# Example usage:
# retrieved_data = retrieve_vulnerabilities(VULNERABILITIES_DATABASE_PATH, limit=5)

# # Print retrieved vulnerabilities
# for index, vulnerability in enumerate(retrieved_data, start=1):
#     print(f"\nVulnerability {index}:")
#     print("CVE ID:", vulnerability['cve_id'])
#     print("Description:", vulnerability['description'])
#     print("Severity:", vulnerability['severity'])
#     print("Affected Software:", vulnerability['affected_software'])
#     print("References:", vulnerability['references_data'])

# check_vulnerabilities()