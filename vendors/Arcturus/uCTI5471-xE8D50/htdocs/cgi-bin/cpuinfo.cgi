#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uC5471DSP /proc/cpuinfo</title></head><body>"
echo "<H2>uC5471DSP /proc/cpuinfo</H2>"
echo

echo "<pre>"
cat /proc/cpuinfo
echo "</pre>"

echo
echo
echo "</body></html>"

