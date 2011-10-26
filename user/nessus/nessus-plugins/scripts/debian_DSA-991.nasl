# This script was automatically generated from the dsa-991
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jean-Sébastien Guay-Leroux discovered a buffer overflow in zoo, a
utility to manipulate zoo archives, that could lead to the execution
of arbitrary code when unpacking a specially crafted zoo archive.
For the old stable distribution (woody) this problem has been fixed in
version 2.10-9woody0.
For the stable distribution (sarge) this problem has been fixed in
version 2.10-11sarge0.
For the unstable distribution (sid) this problem has been fixed in
version 2.10-17.
We recommend that you upgrade your zoo package.


Solution : http://www.debian.org/security/2006/dsa-991
Risk factor : High';

if (description) {
 script_id(22857);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "991");
 script_cve_id("CVE-2006-0855");
 script_bugtraq_id(16790);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA991] DSA-991-1 zoo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-991-1 zoo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zoo', release: '', reference: '2.10-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zoo is vulnerable in Debian .\nUpgrade to zoo_2.10-17\n');
}
if (deb_check(prefix: 'zoo', release: '3.0', reference: '2.10-9woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zoo is vulnerable in Debian 3.0.\nUpgrade to zoo_2.10-9woody0\n');
}
if (deb_check(prefix: 'zoo', release: '3.1', reference: '2.10-11sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zoo is vulnerable in Debian 3.1.\nUpgrade to zoo_2.10-11sarge0\n');
}
if (deb_check(prefix: 'zoo', release: '3.1', reference: '2.10-11sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zoo is vulnerable in Debian sarge.\nUpgrade to zoo_2.10-11sarge0\n');
}
if (deb_check(prefix: 'zoo', release: '3.0', reference: '2.10-9woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zoo is vulnerable in Debian woody.\nUpgrade to zoo_2.10-9woody0\n');
}
if (w) { security_hole(port: 0, data: desc); }
