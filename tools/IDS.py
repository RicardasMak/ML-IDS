import csv
from datetime import datetime
import os
import pickle
import scapy.all as scapy
import time
import collections
from tools.binarize_flags import tcp_flags
from sklearn.preprocessing import StandardScaler

group_pkg = []
time_to_count = time.time() + 3
sc = StandardScaler()

counter_norma = 0
count_dos = 0
count_scan = 0
count_brute = 0

# function receives boolean to start capturing packets.
# into the class will be passed variables such as
# start boolean, nic (interface name), ip (localhost ip)
# and model_ml which contains name of the machine learning model
def ids(start, nic, ip, model_ml):
    if start:
        global local_ip
        global model
        model = model_ml
        local_ip = ip
        print('Started IDS (Ctrl+c to stop)')
        scapy.sniff(iface=nic, filter='ip', store=False, prn=capture_packet)


# This function will add headers if log_ids.csv file does not exist
def log_to_csv(pkg, attack_type):
    if not os.path.exists('log_ids.csv'):
        try:
            with open('log_ids.csv', 'w', newline='') as file:
                write = csv.writer(file)
                write.writerow(['Time', 'SRC IP', 'DST IP', 'DST PORT', 'Window', 'IP Length', 'ACK', 'SYN', 'FIN',
                                'URG', 'PSH', 'RST', 'Volume', 'Has Pass', 'Classification'])
        except IOError as e:
            print('Error on attempt to write labels: ', e)

    try:
        with open('log_ids.csv', 'a', newline='') as f:
            w = csv.writer(f)
            w.writerow([datetime.now().time(), pkg['src_ip'], pkg['dst_ip'], pkg['dst_port'], pkg['window'],
                        pkg['ip_len'], pkg['A'], pkg['S'],
                        pkg['F'], pkg['U'], pkg['P'], pkg['R'],
                        pkg['volume'], pkg['has_pass'], attack_type])
    except IOError as e:
        print('Error on recording traffic: ', e)

# Count and binarize TCP flags and destination port. After pass them into machine learning model
def tcp_counter(pkg):
    src_ip = pkg['IP'].src
    dst_ip = pkg['IP'].dst

    dst_port = pkg['TCP'].dport
    dataofs = pkg['TCP'].dataofs
    window = pkg['TCP'].window
    ip_lenght = pkg['IP'].len

    flags_dictionary = tcp_flags(pkg)
    has_pass = 0

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
    global time_to_count, results

    # initialize packet count with same selected features every 3sec
    if time.time() > time_to_count:
        count = collections.Counter([tuple(d.items()) for d in group_pkg])
        sorted_pkg = [dict(k) | {c: v} for (*k, (c, _)), v in count.items()]

        time_to_count = time.time() + 3
        group_pkg.clear()

        # load ML model
        load = pickle.load(open(model, 'rb'))

        for pkg in sorted_pkg:

            pkg_copy = pkg.copy()
            pkg_copy.pop('src_ip')
            pkg_copy.pop('dst_ip')

            # transform dictionary into a list
            pkg_list = list(pkg_copy.values())

            # predict packet
            results = load.predict(([pkg_list]))

            attack_type =''
            global count_brute, count_scan, count_dos, counter_norma

            if results == 1:
                attack_type = 'brute force'
                count_brute += pkg['volume']

            elif results == 2:
                attack_type = 'DoS'
                count_dos += pkg['volume']

            elif results == 3:
                attack_type = 'Scan'
                count_scan += pkg['volume']
            else:
                attack_type = 'benign'
                counter_norma += pkg['volume']

            print('Benign pkg: {}'.format(counter_norma),
                  'Brute force pkg: {}'.format(count_brute),
                  'Scan pkg: {}'.format(count_scan),
                  'Flood pkg: {}'.format(count_dos), end='\r')

            # Log packets details into the CSV
            log_to_csv(pkg, attack_type)

# Start capturing packets, pre-processing packages and write to csv file
def capture_packet(packet):
    if packet.haslayer('TCP') and packet['IP'].src != local_ip:
        tcp_counter(packet)
