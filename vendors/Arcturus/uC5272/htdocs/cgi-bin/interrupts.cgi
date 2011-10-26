#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uC5272 /proc/interrupts</title></head><body>"
echo "<H2>uC5272 /proc/interrupts</H2>"
echo

echo "<pre>"
cat /proc/interrupts
echo "</pre>"

echo
echo
echo "</body></html>"

