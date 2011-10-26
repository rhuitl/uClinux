# This script was automatically generated from the dsa-693
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Kevin Finisterre discovered a buffer overflow in luxman, an SVGA based
PacMan clone, that could lead to the execution of arbitrary commands
as root.
For the stable distribution (woody) this problem has been fixed in
version 0.41-17.2.
For the unstable distribution (sid) this problem has been fixed in
version 0.41-20.
We recommend that you upgrade your luxman package.


Solution : http://www.debian.org/security/2005/dsa-693
Risk factor : High';

if (description) {
 script_id(17324);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "693");
 script_cve_id("CVE-2005-0385");
 script_bugtraq_id(12797);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA693] DSA-693-1 luxman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-693-1 luxman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'luxman', release: '3.0', reference: '0.41-17.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package luxman is vulnerable in Debian 3.0.\nUpgrade to luxman_0.41-17.2\n');
}
if (deb_check(prefix: 'luxman', release: '3.1', reference: '0.41-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package luxman is vulnerable in Debian 3.1.\nUpgrade to luxman_0.41-20\n');
}
if (deb_check(prefix: 'luxman', release: '3.0', reference: '0.41-17.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package luxman is vulnerable in Debian woody.\nUpgrade to luxman_0.41-17.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
