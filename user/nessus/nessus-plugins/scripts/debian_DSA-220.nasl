# This script was automatically generated from the dsa-220
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cross site scripting vulnerability has been discovered in
squirrelmail, a feature-rich webmail package written in PHP4.
Squirrelmail doesn\'t sanitize user provided variables in all places,
leaving it vulnerable to a cross site scripting attack.
For the current stable distribution (woody) this problem has been
fixed in version 1.2.6-1.3.  The old stable distribution (potato) is
not affected since it doesn\'t contain a squirrelmail package.
An updated package for the unstable distribution (sid) is
expected soon.
We recommend that you upgrade your squirrelmail package.


Solution : http://www.debian.org/security/2003/dsa-220
Risk factor : High';

if (description) {
 script_id(15057);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "220");
 script_cve_id("CVE-2002-1341");
 script_bugtraq_id(6302);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA220] DSA-220-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-220-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.0.\nUpgrade to squirrelmail_1.2.6-1.3\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian woody.\nUpgrade to squirrelmail_1.2.6-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
