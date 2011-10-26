# This script was automatically generated from the dsa-329
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered that osh, a shell intended to restrict the
actions of the user, contains two buffer overflows, in processing
environment variables and file redirections.  These vulnerabilities
could be used to execute arbitrary code, overriding any restrictions
placed on the shell.
For the stable distribution (woody) this problem has been fixed in
version 1.7-11woody1.
The old stable distribution (potato) is affected by this problem, and
may be fixed in a future advisory on a time-available basis.
For the unstable distribution (sid) this problem is fixed in version
1.7-12.
We recommend that you update your osh package.


Solution : http://www.debian.org/security/2003/dsa-329
Risk factor : High';

if (description) {
 script_id(15166);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "329");
 script_cve_id("CVE-2003-0452");
 script_bugtraq_id(7992, 7993);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA329] DSA-329-1 osh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-329-1 osh");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'osh', release: '3.0', reference: '1.7-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osh is vulnerable in Debian 3.0.\nUpgrade to osh_1.7-11woody1\n');
}
if (deb_check(prefix: 'osh', release: '3.1', reference: '1.7-12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osh is vulnerable in Debian 3.1.\nUpgrade to osh_1.7-12\n');
}
if (deb_check(prefix: 'osh', release: '3.0', reference: '1.7-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osh is vulnerable in Debian woody.\nUpgrade to osh_1.7-11woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
