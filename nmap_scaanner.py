import nmap
import socket

# Get the local IP address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ip_address = s.getsockname()[0]
s.close()

# Get the subnet
subnet = ip_address.rsplit('.', 1)[0] + '.0/24'

# Create a PortScanner object
nm = nmap.PortScanner()

# Scan the subnet
nm.scan(hosts=subnet, arguments='-p 1-1024')

print(nm.all_hosts())
# Iterate over the scan results
for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)
        lport = nm[host][proto].keys()
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))