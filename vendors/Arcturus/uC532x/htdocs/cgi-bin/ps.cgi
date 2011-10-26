#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>Process table</title></head><body>"
echo "<h2>Process table</h2>"
echo

echo "<pre>"
ps
echo "</pre>"

echo
echo
echo "</body></html>"

