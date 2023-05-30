import socket
# import termcolor

def scan(target, ports):
    print('\n' + ' Starting scan for ' + str(target))
    for port in range(1, ports):
        scan_port(target, port)

def scan_port(ipAddress, port):
    try:
        sock = socket.socket()

        sock.connect((ipAddress, port))
        print("[+] Port Opened " + str(port))

        sock.close()
    except :
        print("[-] Port Closed " + str(port))

#Ask user for targets - single target or multiple
targets = input("[*] Enter target to scan (split by ,): ")

#Ask user how many ports they want to scan
ports = int(input("[*] Enter how many ports you want to scan: "))

#Check if comma exists - if true, user entered multiple
if ',' in targets:
    print("[*] Scanning multiple targets")
    #foreach ip address - split with comma
    for ip_addr in targets.split(','):
        scan(ip_addr.strip(' '), ports) #scan each ip with the specified ports
else:
    scan(targets, ports) #else scan the single ip with the specified ports
