# This script was automatically generated from the dsa-929
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp from the Debian Security Audit project discovered a buffer
overflow in petris, a clone of the Tetris game, which may be exploited
to execute arbitary code with group games privileges.
The old stable distribution (woody) does not contain the petris package.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.1-4sarge0.
For the unstable distribution the package will be updated shortly.
We recommend that you upgrade your petris package.


Solution : http://www.debian.org/security/2006/dsa-929
Risk factor : High';

if (description) {
 script_id(22795);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "929");
 script_cve_id("CVE-2005-3540");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA929] DSA-929-1 petris");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-929-1 petris");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'petris', release: '3.1', reference: '1.0.1-4sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package petris is vulnerable in Debian 3.1.\nUpgrade to petris_1.0.1-4sarge0\n');
}
if (deb_check(prefix: 'petris', release: '3.1', reference: '1.0.1-4sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package petris is vulnerable in Debian sarge.\nUpgrade to petris_1.0.1-4sarge0\n');
}
if (w) { security_hole(port: 0, data: desc); }
