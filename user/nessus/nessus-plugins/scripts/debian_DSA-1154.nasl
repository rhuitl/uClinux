# This script was automatically generated from the dsa-1154
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
James Bercegay of GulfTech Security Research discovered a vulnerability
in SquirrelMail where an authenticated user could overwrite random
variables in the compose script. This might be exploited to read or
write the preferences or attachment files of other users.
For the stable distribution (sarge) this problem has been fixed in
version 1.4.4-9.
For the unstable distribution (sid) this problem has been fixed in
version 1.4.8-1.
We recommend that you upgrade your squirrelmail package.


Solution : http://www.debian.org/security/2006/dsa-1154
Risk factor : High';

if (description) {
 script_id(22696);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1154");
 script_cve_id("CVE-2006-4019");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1154] DSA-1154-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1154-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squirrelmail', release: '', reference: '1.4.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian .\nUpgrade to squirrelmail_1.4.8-1\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.1.\nUpgrade to squirrelmail_1.4.4-9\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian sarge.\nUpgrade to squirrelmail_1.4.4-9\n');
}
if (w) { security_hole(port: 0, data: desc); }
