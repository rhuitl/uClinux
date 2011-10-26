#!/bin/sh

echo Content-type: text/html
echo
echo "<html><body><pre>"
echo "CPU Status"
cat /proc/cpuinfo
echo
echo
echo "Memory Status"
cat /proc/meminfo
echo "</body></html>"
