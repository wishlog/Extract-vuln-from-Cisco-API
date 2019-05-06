import json
import os
import re
import sys
import csv


from natsort import natsorted, ns
from decimal import Decimal
from pprint import pprint

ios_versions = {
       	'12.2\(55\)SE10'
}



with open('output.csv', 'w') as csvfile:
       	writer = csv.writer(csvfile)
       	for ios_version in ios_versions:
       		try:
       			ios = os.popen('CLIENT_ID="xxxxxxxxxxxxxxxxxxx" CLIENT_SECRET="xxxxxxxxxxxxxxxxx" openVulnQuery --ios ' + ios_version + " 2> /dev/null").read()
       			#print('IOS version: ' + ios_version.replace('\\', ''))
       			entries = json.loads(ios)

       			#with open('12.1.js') as f:
       			#      	entries = json.load(f)
       			cvss = {'low':0, 'medium':0, 'high':0, 'critical':0}
       			vuln_desc = ""
       			fixed = []

       			#pprint(data)
       			for entry in entries:
       				for each_version in entry['first_fixed']:
       					fixed.append(each_version)
       				if entry["sir"] == 'Low' :
       					vuln_desc += 'Low: ' + entry["advisory_title"] + '\n'
       					vuln_desc += 'CVEs: \n'
       					for cve in entry['cves']:
       						vuln_desc += '  ' + cve + '\n'
       					cvss['low'] += 1
       				elif entry["sir"] == "Medium":
       					vuln_desc += 'Medium: ' + entry["advisory_title"] + '\n'
       					vuln_desc += 'CVEs: ' + '\n'
       					for cve in entry['cves']:
       						vuln_desc += '  ' + cve + '\n'
       					cvss['medium'] += 1
       				elif entry["sir"] == "High" :
       					vuln_desc += 'High: ' + entry["advisory_title"] + '\n'
       					vuln_desc += 'CVEs: ' + '\n'
       					for cve in entry['cves']:
       						vuln_desc += '  ' + cve + '\n'
       					cvss['high'] += 1
       				else :
       					vuln_desc += 'Critical: ' + entry["advisory_title"] + '\n'
       					vuln_desc += 'CVEs: ' + '\n'
       					for cve in entry['cves']:
       						vuln_desc += '  ' + cve + '\n'
       					cvss['critical'] += 1

       			#Print to output
       			#sys.stdout.write(ios_version.replace('\\', '') + '\t' + str(cvss['low']) + '\t' + str(cvss['medium']) + '\t' + str(cvss['high']) + '\t' + str(cvss['critical']) + '\t' + str(natsorted(fixed, reverse=True)[0]))

       			#Identify version 12's IOS:
       			v = ""
       			first_fixed_versions = natsorted(fixed, reverse=True)
       			if re.match("12\.", ios_version):
       				for v in first_fixed_versions:
       					if re.match("12\.*", v):
       						break

       			#Print to file in csv format:
       			writer.writerow([ios_version.replace('\\', ''),str(cvss['low']),str(cvss['medium']),str(cvss['high']),str(cvss['critical']),str(natsorted(fixed, reverse=True)[0]),v,vuln_desc])

       			print("processing: " + ios_version.replace('\\', ''))

       			#Stats in case
       			#print('\n\nlow: %d' %cvss['low'])
       			#print('medium: %d' %cvss['medium'])
       			#print('high: %d' %cvss['high'])
       			#print('critical: %d' %cvss['critical'])
       			#print('COMBINED FIRST FIXED OR NOT AFFECTED: ' + str(natsorted(fixed, reverse=True)))

       		except:
       			#print to output
       			print(ios_version.replace('\\', '') + '\t' + 'error')

       			#Print to file in csv format:
       			writer.writerow([ios_version.replace('\\', ''), 'error'])
