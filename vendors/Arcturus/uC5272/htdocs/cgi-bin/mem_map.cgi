#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uC5272 memory map</title></head><body>"
echo "<H2>uC5272 memory map</H2>"
echo

echo "<pre>"
if [ -f /proc/mem_map ]; then
    cat /proc/mem_map
elif [ -f /proc/maps ]; then
    cat /proc/maps
else
    echo "Memory map info is not available for this build."
fi
echo "</pre>"

echo
echo
echo "</body></html>"

