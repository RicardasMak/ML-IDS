"""
This class is used to check users input (IP) with regular expression.
"""
import re


# Check regular expression for attackers ip
def check_ip():
    ip = input('\nPlease enter attackers IP: ')

    ip_matcher = re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ip)

    if ip_matcher:
        return ip
    else:
        while not ip_matcher:
            print('Wrong format of IP')
            ip = input('\nPlease enter attackers IP: ')
            ip_matcher = re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ip)

    return ip





