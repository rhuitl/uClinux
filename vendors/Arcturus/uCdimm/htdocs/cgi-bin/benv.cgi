#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uCbootloader environment</title></head><body>"
echo "<h2>uCbootloader environment</h2>"
echo

echo "<pre>"
printbenv -q
echo "</pre>"

echo
echo
echo "</body></html>"

