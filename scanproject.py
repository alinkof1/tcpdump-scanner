#! /usr/bin/env python

#Alex Linkoff
#Project3: Network Scan Detection
#Due: May 22nd, 2016

import glob
import re
import sys
from optparse import OptionParser

#initialize global nmap type counters
sS_sV_count = 0
F_count = 0
sn_count = 0

#add option to run code in real time, check commandline arguments for "--online" option
def check_for_option():
	parser = OptionParser()
	parser.add_option("--online",action="store_const",const=1, dest="flag", help="run code on real-time")
	options,args = parser.parse_args()
	if (options.flag == 1):
		return True
	else:
		return False

#if information is present that is piped to python script, store it in piped_data
def read_pipe():
	piped_data = sys.stdin.readline()
	return piped_data

#provides a function key for sorting the log files into ascending order
def sort_logs(logs):
	log_list = numbers.split(logs)
	log_list[1::2] = map(int, log_list[1::2])
	return log_list
	
#takes in tcpdump log or piped data to find information about nmap scan conducted and when address is scanned
def find_nmaps(tcpdump_lines):

	#initialize the nmap type, arp nmap flag, and # identifier
	nmap = []
	sS_sV_flag = 0
	nmap_id = 0
	nmap_found = 0

	#set the nmap counts to 0 for this particular logfile
	global sS_sV_count
	global F_count
	global sn_count

	sS_sV_count = 0
	F_count = 0
	sn_count = 0

	#intialize scanner_ip, victim_ip, and timestamp
	scanner = None
	victim = None
	time = None

	#initialize the scan start and stop iteration within the individual tcpdump log file
	scan_start = 0
	scan_count = 0
	scan_end = 0

	#initialize the scan starting ip
	firstscan_ip = ""
	temp_ip = ""
	debug = 0


	for i,w in enumerate(tcpdump_lines):

		#if scan isn't being counted yet:
		#do preliminary checks now to look for indicators
		if (scan_start == 0):

			#look for first arp request, store the first scanned ip
			#set the scan_start flag, indicating the start of a new scan
			if(re.findall(r'ARP, Request',w)):
				firstscan_ip = get_scan_ip(w)
				scan_start = 1
				scan_end = 0
				scan_count = 0
		else:
			#find next arp request with first victim's name in it
			#or essentially the end of the last scan being run
			if(re.findall(r'ARP, Request',w)):

				#get ip of current line to see if it's same as first scanned ip
				#check for the first ip scanned, to ensure the last scan really ended
				temp_ip = get_scan_ip(w)
				if (temp_ip == firstscan_ip):
					#firstscan_ip = get_scan_ip(w)
					scan_end = 1
				else: 		#if first scanned ip isn't found, then scan is "still happening"
					scan_count += 1

			#look for sS, sV indicators	and set their flags
			if(w.find("Flags [S.],")) and sS_sV_flag == 0:
				sS_sV_flag = 1
			elif(w.find("Flags [S],")) and sS_sV_flag == 0:
				sS_sV_flag = 1

		#initialize the reverse indexer here
		j=0

		#parse through information and find the line that details nmap scanner information
		if(re.findall(r'ARP, Reply',w)):

			#set current index of log into j, so we can reverse index from here later
			j=i
			line = w

			#obtain reply ip addr from the relevant data line
			reply_ip = get_reply_ip(line)

			#search for first instance of "ARP, Request" before the "ARP, Reply" line to get info
			#make sure this also has the ip of the reply in it
			while(1):
				if(re.findall(r'ARP, Request',line)):
				#if(line.find('ARP, Request')):
					temp_ip = get_scan_ip(line)
					if(reply_ip == temp_ip):
						#print line
						break
				if(j==0):
					#print "temp_ip: %s" % temp_ip
					#print "reply_ip: %s" % reply_ip
					break
				else:
					j = j-1
					line = tcpdump_lines[j]

			#obtain victim, scanner, and time of scan from the relevant data line
			victim, scanner, time = get_data(line)

			#print the attacking/scanner vm's ip to console and to outputfile
			print ('		scanned from %s at %s\n' %(scanner, time))
			with open("output_scan.txt", 'a') as output_scan:
				output_scan.write('		scanned from %s at %s\n' %(scanner, time))

			#if scan end was detected, ie- first ip scanned was scanned again
			#check here if the nmap_id indicates that the scan was "inconclusive"
			if(scan_end == 1):
				nmap.append(nmap_type(scan_count, sS_sV_flag))
				scan_start = 0	
				scan_count = 0
				sS_sV_flag = 2  #sS/sV scan already seen, so don't report any more

			#if the scan hasn't ended yet and we've looked at every ip, then end the scan manually
			else:
				if(scan_count > 255):
					scan_end = 1
					nmap.append(nmap_type(scan_count, sS_sV_flag))
					sS_sV_flag = 2
	for k,v in enumerate(nmap):
		print ('		NMAP type %d: %s\n' % (k+1,v))
		with open("output_scan.txt", 'a') as output_scan:
			output_scan.write('		nmap type %d: %s\n' % (k+1,v))


#parse through ARP, Request packet to find the first ip scanned in nmap scan
def get_scan_ip(line):
	victim = " "

	if(re.findall(r'Broadcast',line)):
		data_line = line.split(" ")
		victim = data_line[4]
	elif(re.findall(r'oui',line)):
		data_line = line.split(" ")
		victim = data_line[4]
	else:
		data_line = line.split(" ")
		victim = data_line[4]
	return victim


#finds the reply ip address seen in the ARP, Reply packet
#use this ip when searching reverse indexing the list to search for the attacking ip address and timestamp
def get_reply_ip(line):
	reply_ip = None
	if(line.find("Arp, Reply")):
		data_line = line.split(" ")
		reply_ip = data_line[3]
	return reply_ip


#checks different cases to make sure it parses the data line correctly to
#obtain the victim's ip, scanner's ip, and timestamp
def get_data(line):

	victim = None
	scanner = None
	time = None

	if(re.findall(r'Broadcast',line)):
		data_line = line.split(" ")
		victim = data_line[4]
		scanner = data_line[7][:-1]
		time = data_line[0]
	elif(re.findall(r'oui',line)):
		data_line = line.split(" ")
		victim = data_line[4]
		scanner = data_line[9][:-1]
		time = data_line[0]
	else:
		data_line = line.split(" ")
		victim = data_line[4]
		scanner = data_line[6][:-1]
		time = data_line[0]
	return victim,scanner,time

#take the difference between the end and start of nmap scans
#to find the most-likely nmap scan
def nmap_type(scan_count, sS_sV_flag):
	global sS_sV_count
	global F_count
	global sn_count

	if scan_count > 150 and scan_count < 300: #250
		F_count += 1
		return "nmap -F"
	elif sS_sV_flag == 1: #nmap -sS/ nmap -sV
		sS_sV_count += 1
		if sS_sV_count > 1:
			return "no scan"
		else:
			return "nmap -sS/ nmap -sV"
	elif scan_count < 25 and scan_count > 0: #noise/ignore case?
		return "no scan"
	elif scan_count == 0:
		sn_count += 1
		if sn_count > 1:
			return "no scan"
		else:
			return "nmap -sn"
	else:
		return "no scan"



#---------------------------------START Main Program--------------------------------------#

#check if code is run in real time:
realtime_flag = check_for_option()

#set first run through flag
first = 1

#iterate through logfiles in ascending order if no piped data to python script
if (not realtime_flag):		#piped_data):
	piped_flag = False

	#sort the logs to be in ascending order
	numbers = re.compile(r'(\d+)')

	#iterate through the log files
	for logfile in sorted(glob.glob('*.log'), key=sort_logs):
		with open(logfile, 'r') as logfile_in:
			log = logfile_in.read()

		log_lines = log.split('\n')

		if first == 1:
			print ("%s -->\n" % logfile)
			with open("output_scan.txt", 'w') as output_scan:
				output_scan.write("%s -->\n" % logfile)
			first = 0
		else:
			print ("%s -->\n" % logfile)
			with open("output_scan.txt", 'a') as output_scan:
				output_scan.write("%s -->\n" % logfile)


		find_nmaps(log_lines)

else:
	#check for piped data to program (set flag if data is piped):
	piped_data = read_pipe()
	piped_lines = piped_data.split('\n')

	with open("output_scan.txt", 'w') as output_scan:
			output_scan.write("real_time -->\n")

	find_nmaps(piped_lines)