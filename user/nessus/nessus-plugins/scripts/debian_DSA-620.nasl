# This script was automatically generated from the dsa-620
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in Perl, the popular
scripting language.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Jeroen van Wolffelaar discovered that the rmtree() function in the
    File::Path module removes directory trees in an insecure manner
    which could lead to the removal of arbitrary files and directories
    through a symlink attack.
    Trustix developers discovered several insecure uses of temporary
    files in many modules which allow a local attacker to overwrite
    files via a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 5.6.1-8.8.
For the unstable distribution (sid) these problems have been fixed in
version 5.8.4-5.
We recommend that you upgrade your perl packages.


Solution : http://www.debian.org/security/2004/dsa-620
Risk factor : High';

if (description) {
 script_id(16073);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "620");
 script_cve_id("CVE-2004-0452", "CVE-2004-0976");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA620] DSA-620-1 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-620-1 perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libcgi-fast-perl', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcgi-fast-perl is vulnerable in Debian 3.0.\nUpgrade to libcgi-fast-perl_5.6.1-8.8\n');
}
if (deb_check(prefix: 'libperl-dev', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libperl-dev is vulnerable in Debian 3.0.\nUpgrade to libperl-dev_5.6.1-8.8\n');
}
if (deb_check(prefix: 'libperl5.6', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libperl5.6 is vulnerable in Debian 3.0.\nUpgrade to libperl5.6_5.6.1-8.8\n');
}
if (deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian 3.0.\nUpgrade to perl_5.6.1-8.8\n');
}
if (deb_check(prefix: 'perl-base', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-base is vulnerable in Debian 3.0.\nUpgrade to perl-base_5.6.1-8.8\n');
}
if (deb_check(prefix: 'perl-debug', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-debug is vulnerable in Debian 3.0.\nUpgrade to perl-debug_5.6.1-8.8\n');
}
if (deb_check(prefix: 'perl-doc', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-doc is vulnerable in Debian 3.0.\nUpgrade to perl-doc_5.6.1-8.8\n');
}
if (deb_check(prefix: 'perl-modules', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-modules is vulnerable in Debian 3.0.\nUpgrade to perl-modules_5.6.1-8.8\n');
}
if (deb_check(prefix: 'perl-suid', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-suid is vulnerable in Debian 3.0.\nUpgrade to perl-suid_5.6.1-8.8\n');
}
if (deb_check(prefix: 'perl', release: '3.1', reference: '5.8.4-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian 3.1.\nUpgrade to perl_5.8.4-5\n');
}
if (deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian woody.\nUpgrade to perl_5.6.1-8.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
