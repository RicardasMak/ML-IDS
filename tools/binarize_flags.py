"""
Will binarize flags. If flag is set will use number 1 and if not will set to 0
"""


def tcp_flags(packet):
    flags_dictionary = {'A': 0, 'S': 0, 'F': 0,
                        'U': 0, 'P': 0, 'R': 0}

    flag = packet['TCP'].flags
    flags = str(flag)

    for i in range(len(flags)):
        if flags_dictionary.__contains__(flags[i]):
            flags_dictionary[flags[i]] = 1

    return flags_dictionary
