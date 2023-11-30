import json

# TODO: Add sqlite

# Load NVD JSON data from the specific file
with open('nvdcve-1.1-2023.json') as file:
    nvd_data = json.load(file)

# Extract relevant information
vulnerabilities = []
for cve_item in nvd_data['CVE_Items']:
    cve_id = cve_item['cve']['CVE_data_meta']['ID']
    description = cve_item['cve']['description']['description_data'][0]['value']
    impact = cve_item['impact']
    if impact:
        severity = impact['baseMetricV3']['cvssV3']['baseScore']

    # Extract affected software versions
    affected_software = []
    configurations = cve_item.get('configurations', {}).get('nodes', [])
    for node in configurations:
        if 'cpe_match' in node:
            for cpe_match in node['cpe_match']:
                affected_software_data = {
                    'vendor': cpe_match.get('cpe23Uri', '').split(':')[3],
                    'product': cpe_match.get('cpe23Uri', '').split(':')[4],
                    'version': cpe_match.get('cpe23Uri', '').split(':')[5],
                }
                if len(affected_software_data):
                    affected_software.append(affected_software_data)
    
    # Extract references
    references = []
    for reference_data in cve_item.get('cve', {}).get('references', {}).get('reference_data', []):
        reference = {
            'url': reference_data.get('url', ''),
            'name': reference_data.get('name', ''),
            'source': reference_data.get('refsource', ''),
            # Add more reference-related fields as needed
        }
        references.append(reference)

    # Create a simplified vulnerability entry
    vulnerability = {
        'cve_id': cve_id,
        'description': description,
        'severity': severity,
        'affected_software': affected_software,
        'references': references,
        # Add more fields as needed
    }

    vulnerabilities.append(vulnerability)
    print('\nVulnerabilities: ')
    for vulnerability in vulnerabilities:
        print(vulnerability['affected_software'])

# Display the extracted information for the first vulnerability as an example
print("Example of Extracted Information:")
print("CVE ID:", vulnerabilities[0]['cve_id'])
print("Description:", vulnerabilities[0]['description'])
print("Severity:", vulnerabilities[0]['severity'])
print("Affected Software:", vulnerabilities[0]['affected_software'])
print("References:", vulnerabilities[0]['references'])
