# This script was automatically generated from the dsa-891
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Kevin Finisterre discovered a format string vulnerability in gpsdrive,
a car navigation system, that can lead to the execution of arbitrary
code.
The old stable distribution (woody) does not contain gpsdrive packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.09-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.09-2sarge1.
We recommend that you upgrade your gpsdrive package.


Solution : http://www.debian.org/security/2005/dsa-891
Risk factor : High';

if (description) {
 script_id(22757);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "891");
 script_cve_id("CVE-2005-3523");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA891] DSA-891-1 gpsdrive");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-891-1 gpsdrive");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gpsdrive', release: '', reference: '2.09-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpsdrive is vulnerable in Debian .\nUpgrade to gpsdrive_2.09-2sarge1\n');
}
if (deb_check(prefix: 'gpsdrive', release: '3.1', reference: '2.09-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpsdrive is vulnerable in Debian 3.1.\nUpgrade to gpsdrive_2.09-2sarge1\n');
}
if (deb_check(prefix: 'gpsdrive', release: '3.1', reference: '2.09-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpsdrive is vulnerable in Debian sarge.\nUpgrade to gpsdrive_2.09-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
