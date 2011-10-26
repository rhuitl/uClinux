#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>Kernel messages</title></head><body>"
echo "<h2>Kernel messages</h2>"
echo

echo "<pre>"

if [ ! -f /tmp/kmsg ]; then
  cat /proc/kmsg > /tmp/kmsg &
  sleep 2
fi

cat /tmp/kmsg

echo "</pre>"

echo
echo
echo "</body></html>"

