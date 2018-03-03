#!/bin/python
"""
TLS Handshake Experiments
"""
import subprocess
import time
import os
import sys

def outfile(website):
	return "output_%s.txt" % website

def openssl(website):
	return ("openssl s_client -connect %s:443 > %s" % (website, outfile(website))).split(" ")

def main(args):
	if len(args) != 1:
		print "Usage: %s input_file" % sys.argv[0]
		return 1

	# Make sure the file exists
	input_file = args[0]
	if not os.path.exists(input_file):
		return 1

	# Run tests
	sites = open(input_file, "r").read().splitlines()
	for site in sites:
		print "Starting process..."
		process = subprocess.Popen(openssl(site), cwd=os.getcwd())
		time.sleep(2)
		print "Terminating process"
		process.terminate()


	return 0




if __name__ == "__main__":
	main(sys.argv[1:])