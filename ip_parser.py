import csv
import glob
from collections import OrderedDict, defaultdict
import socket


def detect_threat(csv_file):
    report, time = defaultdict(list), 'unknown'  # creates a dictionary with a default value of []
    with open(csv_file) as f:  # parse csv file
        f = csv.reader(f)
        for row in f:
            if '#' in row[0]:
                if 'SSL' in row[0]:
                    filename = ' '.join(''.join(row).strip('#').split()[0:2]).strip()
                if 'updated:' in row[0]:
                    time = (''.join(row).strip('#').strip('Last updated:').strip())
                continue
            dstip, dstport, title = row[0], row[1], row[2]  # assigns variables to cells
            report[title].append('{}:{}'.format(dstip, dstport))  # adds ip to the correct key in report dictionary

    with open(csv_file.replace('.csv', '.txt'), 'w+') as readout:
        readout.write('{} IP Blacklist Report\n'.format(filename))
        readout.write('({} IPs found at {})\n\n'.format(str(sum([len(v) for v in report.values()])), time))
        report = OrderedDict(sorted(report.items()))  # sorts companies by name
        for x in report:
            readout.write('=== {} ===\n'.format(x))
            for y in sorted(report[x], key=lambda d: socket.inet_pton(socket.AF_INET, d.split(':')[0])):  # sorts IPs
                readout.write(y + '\n')  # writes to .txt file
            readout.write('\n')
        readout.seek(0)
        print('\n' + readout.read())  # prints result
    readout.close()


for file in glob.glob('*.csv'):  # finds all .csv file in current directory
    detect_threat(file)  # performs the function on selected file
