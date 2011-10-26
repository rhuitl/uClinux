#!/bin/sh
echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uCbootloader environment</title></head><body>"
echo "<h2>uCbootloader environment</h2>"
echo

echo "<hr>"
echo "<pre>"
printbenv -q
echo "</pre>"
echo "<hr>"

echo " <h3>Some useful uCbootloader environment variable examples</h3>"

echo "<p>Boot automatically in 5 seconds if there is no user input:</p>"
echo "<pre>"
echo "    setbenv AUTOBOOT=5"
echo "</pre>"

echo "<p>Configure IP addresses on eth0 and eth1:</p>"
echo "<pre>"
echo "    setbenv IPADDR0=192.168.1.200"
echo "    setbenv IPADDR0=dhcp"
echo "    setbenv IPADDR1=dhcp"
echo "</pre>"

echo "<p>You may wish to set explicit IP gateway, DNS server and search"
echo "paths, for example if DHCP is unavailable or does not set them:</p>"
echo "<pre>"
echo "    setbenv GATEWAY=192.168.1.1"
echo "    setbenv NAMESERVER=192.168.1.1"
echo "    setbenv SEARCHPATH=\"arcturusnetworks.com uclinux.org\""
echo "</pre>"

echo "<p>Mount an NFS volume on bootup:</p>"
echo "<pre>"
echo "    setbenv NFSMOUNT=\"192.168.1.1:/tftpboot /mnt\""
echo "</pre>"

echo "<p>To import above environment variables use following method:</p>"
echo "<pre>"
echo "    printbenv -q -e IPADDR0         >> /etc/profile"
echo "    printbenv -q -e IPADDR1         >> /etc/profile"
echo "    printbenv -q -e GATEWAY         >> /etc/profile"
echo "    printbenv -q -e NAMESERVER      >> /etc/profile"
echo "    printbenv -q -e SEARCHPATH      >> /etc/profile"
echo "    printbenv -q -e NFSMOUNT        >> /etc/profile"
echo ""
echo "    . /etc/profile"
echo ""
echo "</pre>"

echo "</body></html>"

