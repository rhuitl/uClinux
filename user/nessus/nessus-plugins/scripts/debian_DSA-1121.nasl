# This script was automatically generated from the dsa-1121
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Peter Bieringer discovered that postgrey, a greylisting
implementation for Postfix, is vulnerable to a format string attack
that allows remote attackers to cause a denial of service to the daemon.
For the stable distribution (sarge) this problem has been fixed in
version 1.21-1sarge1.
For the stable distribution (sarge) this problem has also been fixed
in version 1.21-1volatile4 in the volatile archive.
For the unstable distribution (sid) this problem has been fixed in
version 1.22-1.
We recommend that you upgrade your postgrey package.


Solution : http://www.debian.org/security/2006/dsa-1121
Risk factor : High';

if (description) {
 script_id(22663);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1121");
 script_cve_id("CVE-2005-1127");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1121] DSA-1121-1 postgrey");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1121-1 postgrey");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'postgrey', release: '', reference: '1.22-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgrey is vulnerable in Debian .\nUpgrade to postgrey_1.22-1\n');
}
if (deb_check(prefix: 'postgrey', release: '3.1', reference: '1.21-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgrey is vulnerable in Debian 3.1.\nUpgrade to postgrey_1.21-1sarge1\n');
}
if (deb_check(prefix: 'postgrey', release: '3.1', reference: '1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgrey is vulnerable in Debian sarge.\nUpgrade to postgrey_1\n');
}
if (w) { security_hole(port: 0, data: desc); }
