# This script was automatically generated from the dsa-924
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Kurt Fitzner discovered a buffer overflow in nbd, the network block
device client and server that could potentially allow arbitrary code on
the NBD server.
For the old stable distribution (woody) this problem has been fixed in
version 1.2cvs20020320-3.woody.3.
For the stable distribution (sarge) this problem has been fixed in
version 2.7.3-3sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your nbd-server package.


Solution : http://www.debian.org/security/2005/dsa-924
Risk factor : High';

if (description) {
 script_id(22790);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "924");
 script_cve_id("CVE-2005-3534");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA924] DSA-924-1 nbd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-924-1 nbd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nbd-client', release: '3.0', reference: '1.2cvs20020320-3.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nbd-client is vulnerable in Debian 3.0.\nUpgrade to nbd-client_1.2cvs20020320-3.woody.3\n');
}
if (deb_check(prefix: 'nbd-server', release: '3.0', reference: '1.2cvs20020320-3.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nbd-server is vulnerable in Debian 3.0.\nUpgrade to nbd-server_1.2cvs20020320-3.woody.3\n');
}
if (deb_check(prefix: 'nbd-client', release: '3.1', reference: '2.7.3-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nbd-client is vulnerable in Debian 3.1.\nUpgrade to nbd-client_2.7.3-3sarge1\n');
}
if (deb_check(prefix: 'nbd-server', release: '3.1', reference: '2.7.3-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nbd-server is vulnerable in Debian 3.1.\nUpgrade to nbd-server_2.7.3-3sarge1\n');
}
if (deb_check(prefix: 'nbd', release: '3.1', reference: '2.7.3-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nbd is vulnerable in Debian sarge.\nUpgrade to nbd_2.7.3-3sarge1\n');
}
if (deb_check(prefix: 'nbd', release: '3.0', reference: '1.2cvs20020320-3.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nbd is vulnerable in Debian woody.\nUpgrade to nbd_1.2cvs20020320-3.woody.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
