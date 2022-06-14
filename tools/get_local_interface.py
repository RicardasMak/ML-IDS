"""
This class is used to get local interface details such as nic name ip address and ports which are open
"""
import psutil
import netifaces as ni
import socket


# Will return local hosts IP address
def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))

        ip = s.getsockname()[0]
        s.close()
    except socket.error as e:
        print('Error obtaining localhost IP address:', e)
    else:
        return ip


# Will return local hosts NIC name which matches local hosts ip
# As well will return NIC ip address
def get_nic_name():
    addrs = psutil.net_if_addrs()

    for nic in addrs:
        try:
            ip = ni.ifaddresses(nic)[ni.AF_INET][0]['addr']
        except ValueError as e:
            print('Error getting interface name: ', e)
        else:
            if ip == get_ip():
                return ip, nic


# Will return open ports on localhost
def get_ports():
    ports = []

    for port in range(1, 65535):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            results = sock.connect_ex(('127.0.0.1', port))
            if results == 0:
                ports.append(port)
            sock.close()
        except socket.error as e:
            print('Error getting port number: ', e)
    return ports
