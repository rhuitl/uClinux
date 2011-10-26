# This script was automatically generated from the dsa-350
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The falconseye package is vulnerable to a buffer overflow exploited
via a long -s command line option.  This vulnerability could be used
by an attacker to gain gid \'games\' on a system where falconseye is
installed.
Note that falconseye does not contain the file permission error
CVE-2003-0359 which affected some other nethack packages.
For the stable distribution (woody) this problem has been fixed in
version 1.9.3-7woody3.
For the unstable distribution (sid) this problem has been fixed in
version 1.9.3-9.
We recommend that you update your falconseye package.


Solution : http://www.debian.org/security/2003/dsa-350
Risk factor : High';

if (description) {
 script_id(15187);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "350");
 script_cve_id("CVE-2003-0358");
 script_bugtraq_id(6806);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA350] DSA-350-1 falconseye");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-350-1 falconseye");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'falconseye', release: '3.0', reference: '1.9.3-7woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package falconseye is vulnerable in Debian 3.0.\nUpgrade to falconseye_1.9.3-7woody3\n');
}
if (deb_check(prefix: 'falconseye-data', release: '3.0', reference: '1.9.3-7woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package falconseye-data is vulnerable in Debian 3.0.\nUpgrade to falconseye-data_1.9.3-7woody3\n');
}
if (deb_check(prefix: 'falconseye', release: '3.1', reference: '1.9.3-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package falconseye is vulnerable in Debian 3.1.\nUpgrade to falconseye_1.9.3-9\n');
}
if (deb_check(prefix: 'falconseye', release: '3.0', reference: '1.9.3-7woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package falconseye is vulnerable in Debian woody.\nUpgrade to falconseye_1.9.3-7woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
