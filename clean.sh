#!/bin/bash

PRIORITY=${PRIORITY:-1024}

# IPv4
while ip -4 rule delete priority ${PRIORITY} 2>/dev/null;
do
	true;
done

# IPv6
while ip -6 rule delete priority ${PRIORITY} 2>/dev/null;
do
	true;
done
