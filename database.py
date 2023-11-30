import json
import sqlite3

with open('nvdcve-1.1-2023.json') as file:
    nvd_data = json.load(file)

# Initialize SQLite database
conn = sqlite3.connect('vulnerabilities.db')
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

# Extract and store relevant information in the database
for cve_item in nvd_data['CVE_Items']:
    cve_id = cve_item['cve']['CVE_data_meta']['ID']
    description = cve_item['cve']['description']['description_data'][0]['value']
    impact = cve_item['impact']
    if impact:
        severity = impact['baseMetricV3']['cvssV3']['baseScore']

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
        for reference_data in cve_item.get('cve', {}).get('references_data', {}).get('reference_data', [])
    ])

    # Insert data into the vulnerabilities table
    cursor.execute('''
        INSERT INTO vulnerabilities (cve_id, description, severity, affected_software, references_data)
        VALUES (?, ?, ?, ?, ?)
    ''', (cve_id, description, severity, affected_software, references_data))

conn.commit()
conn.close()

conn = sqlite3.connect('vulnerabilities.db')
cursor = conn.cursor()

# Fetch the first 5 vulnerabilities from the database (example)
cursor.execute('SELECT * FROM vulnerabilities LIMIT 5')
results = cursor.fetchall()

for result in results:
    print("\nExample of Extracted Information:")
    print("CVE ID:", result[1])
    print("Description:", result[2])
    print("Severity:", result[3])
    print("Affected Software:", json.loads(result[4]))
    print("References:", json.loads(result[5]))

# Close the connection
conn.close()