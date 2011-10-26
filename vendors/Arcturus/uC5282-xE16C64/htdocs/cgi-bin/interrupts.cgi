#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uC5282 /proc/interrupts</title></head><body>"
echo "<H2>uC5282 /proc/interrupts</H2>"
echo

echo "<pre>"
cat /proc/interrupts
echo "</pre>"

echo
echo
echo "</body></html>"

