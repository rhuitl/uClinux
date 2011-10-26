# This script was automatically generated from the dsa-596
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Liam Helmer noticed that sudo, a program that provides limited super
user privileges to specific users, does not clean the environment
sufficiently.  Bash functions and the CDPATH variable are still passed
through to the program running as privileged user, leaving
possibilities to overload system routines.  These vulnerabilities can
only be exploited by users who have been granted limited super user
privileges.
For the stable distribution (woody) these problems have been fixed in
version 1.6.6-1.3.
For the unstable distribution (sid) these problems have been fixed in
version 1.6.8p3.
We recommend that you upgrade your sudo package.


Solution : http://www.debian.org/security/2004/dsa-596
Risk factor : High';

if (description) {
 script_id(15825);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "596");
 script_cve_id("CVE-2004-1051");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA596] DSA-596-2 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-596-2 sudo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 3.0.\nUpgrade to sudo_1.6.6-1.3\n');
}
if (deb_check(prefix: 'sudo', release: '3.1', reference: '1.6.8p3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 3.1.\nUpgrade to sudo_1.6.8p3\n');
}
if (deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian woody.\nUpgrade to sudo_1.6.6-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
