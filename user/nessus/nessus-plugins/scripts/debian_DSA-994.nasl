# This script was automatically generated from the dsa-994
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered a denial of service condition in the free
Civilization server that allows a remote user to trigger a server
crash.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.1-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.8-1.
We recommend that you upgrade your freeciv-server package.


Solution : http://www.debian.org/security/2006/dsa-994
Risk factor : High';

if (description) {
 script_id(22860);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "994");
 script_cve_id("CVE-2006-0047");
 script_bugtraq_id(16975);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA994] DSA-994-1 freeciv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-994-1 freeciv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freeciv', release: '', reference: '2.0.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv is vulnerable in Debian .\nUpgrade to freeciv_2.0.8-1\n');
}
if (deb_check(prefix: 'freeciv', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv is vulnerable in Debian 3.1.\nUpgrade to freeciv_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'freeciv-client-gtk', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-client-gtk is vulnerable in Debian 3.1.\nUpgrade to freeciv-client-gtk_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'freeciv-client-xaw3d', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-client-xaw3d is vulnerable in Debian 3.1.\nUpgrade to freeciv-client-xaw3d_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'freeciv-data', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-data is vulnerable in Debian 3.1.\nUpgrade to freeciv-data_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'freeciv-gtk', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-gtk is vulnerable in Debian 3.1.\nUpgrade to freeciv-gtk_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'freeciv-server', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-server is vulnerable in Debian 3.1.\nUpgrade to freeciv-server_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'freeciv-xaw3d', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-xaw3d is vulnerable in Debian 3.1.\nUpgrade to freeciv-xaw3d_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'freeciv', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv is vulnerable in Debian sarge.\nUpgrade to freeciv_2.0.1-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
