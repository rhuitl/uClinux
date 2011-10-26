#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uC5282 CAN bus status</title></head><body>"
echo "<H2>uC5282 CAN bus status</H2>"
echo

cd /proc/sys/Can

echo "<p>Driver information:</p>"
echo "<table border=1 cellpadding=4>"
echo "  <tr><td>Chipset</td> <td>"
cat Chipset; echo "</td></tr>"
echo "  <tr><td>driver version</td> <td>"
cat version; echo "</td></tr>"
echo "<tr><td>Base</td> <td>"
cat Base; echo "</td></tr>"
echo "<tr><td>IOModel</td> <td>"
cat IOModel; echo "</td></tr>"
echo "<tr><td>IRQ</td> <td>"
cat IRQ; echo "</td></tr>"
echo "<tr><td>debug mask</td> <td>"
cat dbgMask; echo "</td></tr>"
echo "</table>"

echo "<br>"

echo "<table border=1 cellpadding=12>"
echo "<tr><td>"

echo "<p>CAN settings:</p>"
echo "<table border=1 cellpadding=4>"
echo "<tr><td>AccCode</td> <td>"
cat AccCode; echo "</td></tr>"
echo "<tr><td>AccMask</td> <td>"
cat AccMask; echo "</td></tr>"
echo "<tr><td>Baud</td> <td>"
cat Baud; echo "</td></tr>"
echo "<tr><td>Outc</td> <td>"
cat Outc; echo "</td></tr>"
echo "</table>"

echo "</td><td>"

echo "<p>Bus errors:</p>"
echo "<table border=1 cellpadding=4>"
echo "<tr><td>transmit</td> <td>"
cat TxErr; echo "</td></tr>"
echo "<tr><td>receive</td> <td>"
cat RxErr; echo "</td></tr>"
echo "<tr><td>overrun</td> <td>"
cat Overrun; echo "</td></tr>"
echo "<tr><td>timeout</td> <td>"
cat Timeout; echo "</td></tr>"
echo "</table>"

echo "</td></tr>"
echo "</table>"


echo
echo
echo "</body></html>"

