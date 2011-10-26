# This script was automatically generated from the dsa-420
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a security related problem in jitterbug, a
simple CGI based bug tracking and reporting tool.  Unfortunately the
program executions do not properly sanitize input, which allows an
attacker to execute arbitrary commands on the server hosting the bug
database.  As mitigating factors these attacks are only available to
non-guest users, and accounts for these people must be setup by the
administrator making them "trusted".
For the stable distribution (woody) this problem has been fixed in
version 1.6.2-4.2woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.6.2-4.5.
We recommend that you upgrade your jitterbug package.


Solution : http://www.debian.org/security/2004/dsa-420
Risk factor : High';

if (description) {
 script_id(15257);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "420");
 script_cve_id("CVE-2004-0028");
 script_bugtraq_id(9397);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA420] DSA-420-1 jitterbug");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-420-1 jitterbug");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'jitterbug', release: '3.0', reference: '1.6.2-4.2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package jitterbug is vulnerable in Debian 3.0.\nUpgrade to jitterbug_1.6.2-4.2woody2\n');
}
if (deb_check(prefix: 'jitterbug', release: '3.1', reference: '1.6.2-4.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package jitterbug is vulnerable in Debian 3.1.\nUpgrade to jitterbug_1.6.2-4.5\n');
}
if (deb_check(prefix: 'jitterbug', release: '3.0', reference: '1.6.2-4.2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package jitterbug is vulnerable in Debian woody.\nUpgrade to jitterbug_1.6.2-4.2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
