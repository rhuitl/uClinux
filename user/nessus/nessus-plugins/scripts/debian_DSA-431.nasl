# This script was automatically generated from the dsa-431
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Szabo discovered a number of similar bugs in suidperl, a helper
program to run perl scripts with setuid privileges.  By exploiting
these bugs, an attacker could abuse suidperl to discover information
about files (such as testing for their existence and some of their
permissions) that should not be accessible to unprivileged users.
For the current stable distribution (woody) this problem has been
fixed in version 5.6.1-8.6.
For the unstable distribution (sid), this problem will be fixed soon.  Refer
to Debian bug #220486.
We recommend that you update your perl package if you have the
"perl-suid" package installed.


Solution : http://www.debian.org/security/2004/dsa-431
Risk factor : High';

if (description) {
 script_id(15268);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "431");
 script_cve_id("CVE-2003-0618");
 script_bugtraq_id(9543);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA431] DSA-431-1 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-431-1 perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libcgi-fast-perl', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcgi-fast-perl is vulnerable in Debian 3.0.\nUpgrade to libcgi-fast-perl_5.6.1-8.6\n');
}
if (deb_check(prefix: 'libperl-dev', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libperl-dev is vulnerable in Debian 3.0.\nUpgrade to libperl-dev_5.6.1-8.6\n');
}
if (deb_check(prefix: 'libperl5.6', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libperl5.6 is vulnerable in Debian 3.0.\nUpgrade to libperl5.6_5.6.1-8.6\n');
}
if (deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian 3.0.\nUpgrade to perl_5.6.1-8.6\n');
}
if (deb_check(prefix: 'perl-base', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-base is vulnerable in Debian 3.0.\nUpgrade to perl-base_5.6.1-8.6\n');
}
if (deb_check(prefix: 'perl-debug', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-debug is vulnerable in Debian 3.0.\nUpgrade to perl-debug_5.6.1-8.6\n');
}
if (deb_check(prefix: 'perl-doc', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-doc is vulnerable in Debian 3.0.\nUpgrade to perl-doc_5.6.1-8.6\n');
}
if (deb_check(prefix: 'perl-modules', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-modules is vulnerable in Debian 3.0.\nUpgrade to perl-modules_5.6.1-8.6\n');
}
if (deb_check(prefix: 'perl-suid', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-suid is vulnerable in Debian 3.0.\nUpgrade to perl-suid_5.6.1-8.6\n');
}
if (deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian woody.\nUpgrade to perl_5.6.1-8.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
