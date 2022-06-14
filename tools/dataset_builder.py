#!/usr/bin/env python3.9
"""
This class will be capturing packages to create dataset:
1. once the packet is capture it will convert tcp flags from string to binary 1 if flag is set and 0 if not.
2. will count packages which have same features in given time
3. writes to csv
"""
import csv
import os.path
from tools.label_attacks import rules
import scapy.all as scapy
import time
import collections
from tools.binarize_flags import tcp_flags


group_pkg = []
time_to_count = time.time() + 3


# Start sniffer
def sniffer(start, ip, nic, attacker_ip, local_port):
    if start:
        global local_ip
        global malicious_ip
        global lport
        lport = local_port
        malicious_ip = attacker_ip
        local_ip = ip

        scapy.sniff(iface=nic, filter='ip', store=False, prn=capture_packet)


# label packet normal and abnormal, and write into csv traffic
def write_to_csv(sorted_pkg):

    for i in range(len(sorted_pkg)):

        # will check if packet is malicious and will label it
        network = rules(i, sorted_pkg, malicious_ip, lport)

        try:
            with open('log.csv', 'a', newline='') as f:
                w = csv.writer(f)
                w.writerow([sorted_pkg[i]['dst_port'], sorted_pkg[i]['dataofs'], sorted_pkg[i]['window'],
                            sorted_pkg[i]['ip_len'], sorted_pkg[i]['A'], sorted_pkg[i]['S'],
                            sorted_pkg[i]['F'], sorted_pkg[i]['U'], sorted_pkg[i]['P'], sorted_pkg[i]['R'],
                            sorted_pkg[i]['has_pass'], sorted_pkg[i]['volume'], network])
        except IOError as e:
            print('Error on recording traffic: ', e)


# Counts same TCP packages
def tcp_counter(pkg):
    src_ip = pkg['IP'].src
    dst_ip = pkg['IP'].dst

    dst_port = pkg['TCP'].dport
    dataofs = pkg['TCP'].dataofs
    window = pkg['TCP'].window
    ip_lenght = pkg['IP'].len

    flags_dictionary = tcp_flags(pkg)
    has_pass = 0

    # checks if payload contains PASS keyword
    if pkg['TCP'].payload:
        password = bytes(pkg['TCP'].payload).decode('UTF8', 'replace')

        if password.__contains__('PASS'):
            has_pass = 1
            ip_lenght = 0

    temp_dic = {'src_ip': src_ip, 'dst_ip': dst_ip,
                'dst_port': dst_port, 'dataofs': dataofs,
                'window': window, 'ip_len': ip_lenght, 'A': flags_dictionary['A'],
                'S': flags_dictionary['S'], 'F': flags_dictionary['F'],
                'U': flags_dictionary['U'], 'P': flags_dictionary['P'],
                'R': flags_dictionary['R'], 'has_pass': has_pass, 'volume': 0}

    group_pkg.append(temp_dic)
    global time_to_count

    # will start counting packets with same feature every 3sec
    if time.time() > time_to_count:
        count = collections.Counter([tuple(d.items()) for d in group_pkg])
        sorted_pkg = [dict(k) | {c: v} for (*k, (c, _)), v in count.items()]

        # resets timer
        time_to_count = time.time() + 3

        group_pkg.clear()
        write_to_csv(sorted_pkg)


# Start capturing packets, pre-processing packages and write to csv file
def capture_packet(packet):
    if packet.haslayer('TCP') and packet['IP'].src != local_ip:
        tcp_counter(packet)


# Write headers into dataset
if not os.path.exists('log.csv'):
    try:
        with open('log.csv', 'w', newline='') as file:
            write = csv.writer(file)
            write.writerow(['dst_port', 'dataofs', 'window', 'ip_len', 'ACK', 'SYN', 'FIN', 'URG',
                            'PSH', 'RST', 'contains_pass', 'volume', 'Classification'])
    except IOError as e:
        print('Error on attempt to write labels: ', e)
