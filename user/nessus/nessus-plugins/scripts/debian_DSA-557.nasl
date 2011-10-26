# This script was automatically generated from the dsa-557
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler discovered a vulnerability in pppoe, the PPP over Ethernet
driver from Roaring Penguin.  When the program is running setuid root
(which is not the case in a default Debian installation), an attacker
could overwrite any file on the file system.
For the stable distribution (woody) this problem has been fixed in
version 3.3-1.2.
For the unstable distribution (sid) this problem has been fixed in
version 3.5-4.
We recommend that you upgrade your pppoe package.


Solution : http://www.debian.org/security/2004/dsa-557
Risk factor : High';

if (description) {
 script_id(15655);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "557");
 script_cve_id("CVE-2004-0564");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA557] DSA-557-1 rp-pppoe");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-557-1 rp-pppoe");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pppoe', release: '3.0', reference: '3.3-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pppoe is vulnerable in Debian 3.0.\nUpgrade to pppoe_3.3-1.2\n');
}
if (deb_check(prefix: 'rp-pppoe,', release: '3.1', reference: '3.5-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rp-pppoe, is vulnerable in Debian 3.1.\nUpgrade to rp-pppoe,_3.5-4\n');
}
if (deb_check(prefix: 'rp-pppoe,', release: '3.0', reference: '3.3-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rp-pppoe, is vulnerable in Debian woody.\nUpgrade to rp-pppoe,_3.3-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
