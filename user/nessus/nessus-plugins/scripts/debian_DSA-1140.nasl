# This script was automatically generated from the dsa-1140
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Evgeny Legerov discovered that overly large comments can crash gnupg,
the GNU privacy guard - a free PGP replacement.
For the stable distribution (sarge) this problem has been fixed in
version 1.4.1-1.sarge5.
For the unstable distribution (sid) this problem has been fixed in
version 1.4.5-1.
We recommend that you upgrade your gnupg package.


Solution : http://www.debian.org/security/2006/dsa-1140
Risk factor : High';

if (description) {
 script_id(22682);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1140");
 script_cve_id("CVE-2006-3746");
 script_bugtraq_id(19110);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1140] DSA-1140-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1140-1 gnupg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnupg', release: '', reference: '1.4.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg is vulnerable in Debian .\nUpgrade to gnupg_1.4.5-1\n');
}
if (deb_check(prefix: 'gnupg', release: '3.1', reference: '1.4.1-1.sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg is vulnerable in Debian 3.1.\nUpgrade to gnupg_1.4.1-1.sarge5\n');
}
if (deb_check(prefix: 'gnupg', release: '3.1', reference: '1.4.1-1.sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg is vulnerable in Debian sarge.\nUpgrade to gnupg_1.4.1-1.sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
