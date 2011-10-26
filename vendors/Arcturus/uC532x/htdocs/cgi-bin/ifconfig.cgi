#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uC5329 network configuration</title></head><body>"
echo "<H2>uC5329 network configuration</H2>"
echo

echo "<p>Network interface configuration:</p>"
echo "<pre>"
ifconfig
echo "</pre>"

echo "<p>Routing table:</p>"
echo "<pre>"
route -n
echo "</pre>"

echo "<p>resolv.conf:</p>"
echo "<pre>"
cat /etc/resolv.conf
echo "</pre>"

echo
echo
echo "</body></html>"

