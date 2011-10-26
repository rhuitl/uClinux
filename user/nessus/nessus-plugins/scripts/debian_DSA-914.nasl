# This script was automatically generated from the dsa-914
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in horde2, a web application
suite, that allows attackers to insert arbitary script code into the
error web page.
The old stable distribution (woody) does not contain horde2 packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.8-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.2.9-1.
We recommend that you upgrade your horde2 package.


Solution : http://www.debian.org/security/2005/dsa-914
Risk factor : High';

if (description) {
 script_id(22780);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "914");
 script_cve_id("CVE-2005-3570");
 script_bugtraq_id(15409);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA914] DSA-914-1 horde2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-914-1 horde2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'horde2', release: '', reference: '2.2.9-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde2 is vulnerable in Debian .\nUpgrade to horde2_2.2.9-1\n');
}
if (deb_check(prefix: 'horde2', release: '3.1', reference: '2.2.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde2 is vulnerable in Debian 3.1.\nUpgrade to horde2_2.2.8-1sarge1\n');
}
if (deb_check(prefix: 'horde2', release: '3.1', reference: '2.2.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde2 is vulnerable in Debian sarge.\nUpgrade to horde2_2.2.8-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
