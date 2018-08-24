#!/bin/bash

PRIORITY=${PRIORITY:-1024}
while ip rule delete priority ${PRIORITY} 2>/dev/null;
do
	true;
done
