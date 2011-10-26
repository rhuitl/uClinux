# This script was automatically generated from the dsa-943
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jack Louis discovered an integer overflow in Perl, Larry Wall\'s
Practical Extraction and Report Language, that allows attackers to
overwrite arbitrary memory and possibly execute arbitrary code via
specially crafted content that is passed to vulnerable format strings
of third party software.
The old stable distribution (woody) does not seem to be affected by
this problem.
For the stable distribution (sarge) this problem has been fixed in
version 5.8.4-8sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 5.8.7-9.
We recommend that you upgrade your perl packages.


Solution : http://www.debian.org/security/2006/dsa-943
Risk factor : High';

if (description) {
 script_id(22809);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "943");
 script_cve_id("CVE-2005-3962");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA943] DSA-943-1 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-943-1 perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'perl', release: '', reference: '5.8.7-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian .\nUpgrade to perl_5.8.7-9\n');
}
if (deb_check(prefix: 'libcgi-fast-perl', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcgi-fast-perl is vulnerable in Debian 3.1.\nUpgrade to libcgi-fast-perl_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'libperl-dev', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libperl-dev is vulnerable in Debian 3.1.\nUpgrade to libperl-dev_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'libperl5.8', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libperl5.8 is vulnerable in Debian 3.1.\nUpgrade to libperl5.8_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'perl', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian 3.1.\nUpgrade to perl_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'perl-base', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-base is vulnerable in Debian 3.1.\nUpgrade to perl-base_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'perl-debug', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-debug is vulnerable in Debian 3.1.\nUpgrade to perl-debug_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'perl-doc', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-doc is vulnerable in Debian 3.1.\nUpgrade to perl-doc_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'perl-modules', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-modules is vulnerable in Debian 3.1.\nUpgrade to perl-modules_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'perl-suid', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-suid is vulnerable in Debian 3.1.\nUpgrade to perl-suid_5.8.4-8sarge3\n');
}
if (deb_check(prefix: 'perl', release: '3.1', reference: '5.8.4-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian sarge.\nUpgrade to perl_5.8.4-8sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
