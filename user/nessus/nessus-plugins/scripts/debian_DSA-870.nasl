# This script was automatically generated from the dsa-870
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tavis Ormandy noticed that sudo, a program that provides limited super
user privileges to specific users, does not clean the environment
sufficiently.  The SHELLOPTS and PS4 variables are dangerous and are
still passed through to the program running as privileged user.  This
can result in the execution of arbitrary commands as privileged user
when a bash script is executed.  These vulnerabilities can only be
exploited by users who have been granted limited super user
privileges.
For the old stable distribution (woody) this problem has been fixed in
version 1.6.6-1.4.
For the stable distribution (sarge) this problem has been fixed in
version 1.6.8p7-1.2.
For the unstable distribution (sid) this problem has been fixed in
version 1.6.8p9-3.
We recommend that you upgrade your sudo package.


Solution : http://www.debian.org/security/2005/dsa-870
Risk factor : High';

if (description) {
 script_id(22736);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "870");
 script_cve_id("CVE-2005-2959");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA870] DSA-870-1 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-870-1 sudo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sudo', release: '', reference: '1.6.8p9-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian .\nUpgrade to sudo_1.6.8p9-3\n');
}
if (deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 3.0.\nUpgrade to sudo_1.6.6-1.4\n');
}
if (deb_check(prefix: 'sudo', release: '3.1', reference: '1.6.8p7-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 3.1.\nUpgrade to sudo_1.6.8p7-1.2\n');
}
if (deb_check(prefix: 'sudo', release: '3.1', reference: '1.6.8p7-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian sarge.\nUpgrade to sudo_1.6.8p7-1.2\n');
}
if (deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian woody.\nUpgrade to sudo_1.6.6-1.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
