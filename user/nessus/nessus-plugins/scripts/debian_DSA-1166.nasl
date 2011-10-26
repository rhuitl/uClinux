# This script was automatically generated from the dsa-1166
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered a buffer overflow in the loading component
of cheesetracker, a sound module tracking program, which could allow a
maliciously constructed input file to execute arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.9-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.9-6.
We recommend that you upgrade your cheesetracker package.


Solution : http://www.debian.org/security/2006/dsa-1166
Risk factor : High';

if (description) {
 script_id(22708);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1166");
 script_cve_id("CVE-2006-3814");
 script_bugtraq_id(20060723);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1166] DSA-1166-2 cheesetracker");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1166-2 cheesetracker");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cheesetracker', release: '', reference: '0.9.9-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cheesetracker is vulnerable in Debian .\nUpgrade to cheesetracker_0.9.9-6\n');
}
if (deb_check(prefix: 'cheesetracker', release: '3.1', reference: '0.9.9-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cheesetracker is vulnerable in Debian 3.1.\nUpgrade to cheesetracker_0.9.9-1sarge1\n');
}
if (deb_check(prefix: 'cheesetracker', release: '3.1', reference: '0.9.9-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cheesetracker is vulnerable in Debian sarge.\nUpgrade to cheesetracker_0.9.9-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
