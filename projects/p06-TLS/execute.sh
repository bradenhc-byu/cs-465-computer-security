#!/bin/bash

function ossl(){
	echo "Running openssl and getting output from connection with $1"
	# Run OpenSSL
	openssl s_client -connect $1:443 > output_$1.txt &
	# Get its PID
	PID=$!
	# Wait for 1 second to make sure we got all the output
	sleep 1
	# Kill it
	kill $PID
}

ossl lds.org
ossl instructure.com
ossl discover.com
ossl efirstbank.com
ossl mint.com
ossl facebook.com
ossl learningsuite.byu.edu
ossl cs460.byu.edu
ossl gmail.com
ossl stackoverflow.com

exit 0