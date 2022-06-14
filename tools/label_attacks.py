"""
This class is used to label malicious traffic ether benign or malicious.
"""
benign = 0
brute_force = 0
scan = 0
dos = 0


def rules(i, sorted_pkg, malicious_ip, local_port):
    network = 'benign'

    # will check if the packet is a brute force (ftp)
    if sorted_pkg[i]['src_ip'] == malicious_ip and sorted_pkg[i]['has_pass'] == 1 and sorted_pkg[i]['volume'] > 2:

        counter(0, 0, sorted_pkg[i]['volume'], 0)

        return 'bruteforce'

    # will check if SYN packet was sent once or more times as well if port is open to which SYN was sent.
    elif sorted_pkg[i]['S'] == 1 and sorted_pkg[i]['volume'] == 1 and sorted_pkg[i]['src_ip'] == malicious_ip:

        if sorted_pkg[i]['dst_port'] in local_port:

            counter(0, 0, 0, sorted_pkg[i]['volume'])

            return 'benign'
        else:
            counter(0, sorted_pkg[i]['volume'], 0, 0)
            return 'scan'

    # label malicious for xmas scan
    elif sorted_pkg[i]['src_ip'] == malicious_ip and sorted_pkg[i]['U'] == 1 and sorted_pkg[i]['P'] == 1 \
            and sorted_pkg[i]['F'] == 1:

        counter(0, sorted_pkg[i]['volume'], 0, 0)
        return 'scan'

    # label malicious for null scan
    elif sorted_pkg[i]['src_ip'] == malicious_ip and sorted_pkg[i]['U'] == 0 and sorted_pkg[i]['P'] == 0 \
            and sorted_pkg[i]['F'] == 0 and sorted_pkg[i]['A'] == 0 and sorted_pkg[i]['S'] == 0 \
            and sorted_pkg[i]['R'] == 0:

        counter(0, sorted_pkg[i]['volume'], 0, 0)
        return 'scan'

    # label malicious if same packets are being send from same IP address
    elif sorted_pkg[i]['src_ip'] == malicious_ip and sorted_pkg[i]['volume'] > 100:

        counter(sorted_pkg[i]['volume'], 0, 0, 0)
        return 'dos'

    counter(0, 0, 0, sorted_pkg[i]['volume'])
    return network


# function counts packets that was labeled and displays to the user
def counter(dos_f, scan_n, brute_f, benign_n):
    global benign
    global brute_force
    global scan
    global dos

    benign += benign_n
    brute_force += brute_f
    scan += scan_n
    dos += dos_f

    print('Benign pkg: {}'.format(benign),
          'Brute force pkg: {}'.format(brute_force),
          'Scan pkg: {}'.format(scan),
          'Flood pkg: {}'.format(dos), end='\r')
