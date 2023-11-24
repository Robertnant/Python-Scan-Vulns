import nmap
import socket
import json


# Get the local IP address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ip_address = s.getsockname()[0]
s.close()

# Get the subnet
subnet = ip_address.rsplit('.', 1)[0] + '.0/24'
print("Searching in the following subnet:", subnet)



# Create a PortScanner object
nm = nmap.PortScanner()


# Scan the subnet
nm.scan(hosts=subnet, arguments='-sV -p 80 -T5')

class Service:
    def __init__(self, name, version):
        self.name = name
        self.version = version
    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version
        }

class ExposedDevice:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.services = []
    def to_dict(self):
        return {
            "ip_address": self.ip_address,
            "services": [service.to_dict() for service in self.services]
        }


all_exposed_devices = []


print(nm.all_hosts())
# Iterate over the scan results
for ip_address in nm.all_hosts():
    print('----------------------------------------------------')
    print('IP found: %s, with hostname: %s' % (ip_address, nm[ip_address].hostname()))
    for proto in nm[ip_address].all_protocols():
        all_ports = nm[ip_address][proto].keys()
        potential_exposed_device = ExposedDevice(ip_address)
        for port in all_ports:
            state = nm[ip_address][proto][port]['state']
            if state == "open":
                service_name = nm[ip_address][proto][port]['name']
                service_version = nm[ip_address][proto][port]['version']
                print("port open with service name:", service_name, "and version:", service_version)
                service_exposed = Service(service_name, service_version)
                potential_exposed_device.services.append(service_exposed)
        if len(potential_exposed_device.services) != 0:
            all_exposed_devices.append(potential_exposed_device)
                
json_all_exposed_devices = [exposed_device.to_dict() for exposed_device in all_exposed_devices]
print(json_all_exposed_devices)

json_data = {
    "all_exposed_devices": json_all_exposed_devices
}

with open('all_exposed_devices.json', 'w') as json_file:
    json.dump(json_data, json_file, indent=2)

"""
EXAMPLE OF OBJECTS
allExposedDevices = [expostedDevice1, expostedDevice2, ...]
expostedDevice1.ip_address = "192.168.0.1"
exposedDevice1.services [service1, service2, ...]
service1.name
service1.version
"""