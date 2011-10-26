# This script was automatically generated from the dsa-208
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A security hole has been discovered in Safe.pm which is used in all
versions of Perl.  The Safe extension module allows the creation of
compartments in which perl code can be evaluated in a new namespace
and the code evaluated in the compartment cannot refer to variables
outside this namespace.  However, when a Safe compartment has already
been used, there\'s no guarantee that it is Safe any longer, because
there\'s a way for code to be executed within the Safe compartment to
alter its operation mask.  Thus, programs that use a Safe compartment
only once aren\'t affected by this bug.
This problem has been fixed in version 5.6.1-8.2 for the current
stable distribution (woody), in version 5.004.05-6.2 and 5.005.03-7.2
for the old stable distribution (potato) and in version 5.8.0-14 for
the unstable distribution (sid).
We recommend that you upgrade your Perl packages.


Solution : http://www.debian.org/security/2002/dsa-208
Risk factor : High';

if (description) {
 script_id(15045);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "208");
 script_cve_id("CVE-2002-1323");
 script_bugtraq_id(6111);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA208] DSA-208-1 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-208-1 perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'perl-5.004', release: '2.2', reference: '5.004.05-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.004 is vulnerable in Debian 2.2.\nUpgrade to perl-5.004_5.004.05-6.2\n');
}
if (deb_check(prefix: 'perl-5.004-base', release: '2.2', reference: '5.004.05-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.004-base is vulnerable in Debian 2.2.\nUpgrade to perl-5.004-base_5.004.05-6.2\n');
}
if (deb_check(prefix: 'perl-5.004-debug', release: '2.2', reference: '5.004.05-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.004-debug is vulnerable in Debian 2.2.\nUpgrade to perl-5.004-debug_5.004.05-6.2\n');
}
if (deb_check(prefix: 'perl-5.004-doc', release: '2.2', reference: '5.004.05-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.004-doc is vulnerable in Debian 2.2.\nUpgrade to perl-5.004-doc_5.004.05-6.2\n');
}
if (deb_check(prefix: 'perl-5.004-suid', release: '2.2', reference: '5.004.05-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.004-suid is vulnerable in Debian 2.2.\nUpgrade to perl-5.004-suid_5.004.05-6.2\n');
}
if (deb_check(prefix: 'perl-5.005', release: '2.2', reference: '5.005.03-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.005 is vulnerable in Debian 2.2.\nUpgrade to perl-5.005_5.005.03-7.2\n');
}
if (deb_check(prefix: 'perl-5.005-base', release: '2.2', reference: '5.005.03-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.005-base is vulnerable in Debian 2.2.\nUpgrade to perl-5.005-base_5.005.03-7.2\n');
}
if (deb_check(prefix: 'perl-5.005-debug', release: '2.2', reference: '5.005.03-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.005-debug is vulnerable in Debian 2.2.\nUpgrade to perl-5.005-debug_5.005.03-7.2\n');
}
if (deb_check(prefix: 'perl-5.005-doc', release: '2.2', reference: '5.005.03-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.005-doc is vulnerable in Debian 2.2.\nUpgrade to perl-5.005-doc_5.005.03-7.2\n');
}
if (deb_check(prefix: 'perl-5.005-suid', release: '2.2', reference: '5.005.03-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.005-suid is vulnerable in Debian 2.2.\nUpgrade to perl-5.005-suid_5.005.03-7.2\n');
}
if (deb_check(prefix: 'perl-5.005-thread', release: '2.2', reference: '5.005.03-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-5.005-thread is vulnerable in Debian 2.2.\nUpgrade to perl-5.005-thread_5.005.03-7.2\n');
}
if (deb_check(prefix: 'libcgi-fast-perl', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcgi-fast-perl is vulnerable in Debian 3.0.\nUpgrade to libcgi-fast-perl_5.6.1-8.2\n');
}
if (deb_check(prefix: 'libperl-dev', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libperl-dev is vulnerable in Debian 3.0.\nUpgrade to libperl-dev_5.6.1-8.2\n');
}
if (deb_check(prefix: 'libperl5.6', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libperl5.6 is vulnerable in Debian 3.0.\nUpgrade to libperl5.6_5.6.1-8.2\n');
}
if (deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl is vulnerable in Debian 3.0.\nUpgrade to perl_5.6.1-8.2\n');
}
if (deb_check(prefix: 'perl-base', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-base is vulnerable in Debian 3.0.\nUpgrade to perl-base_5.6.1-8.2\n');
}
if (deb_check(prefix: 'perl-debug', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-debug is vulnerable in Debian 3.0.\nUpgrade to perl-debug_5.6.1-8.2\n');
}
if (deb_check(prefix: 'perl-doc', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-doc is vulnerable in Debian 3.0.\nUpgrade to perl-doc_5.6.1-8.2\n');
}
if (deb_check(prefix: 'perl-modules', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-modules is vulnerable in Debian 3.0.\nUpgrade to perl-modules_5.6.1-8.2\n');
}
if (deb_check(prefix: 'perl-suid', release: '3.0', reference: '5.6.1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perl-suid is vulnerable in Debian 3.0.\nUpgrade to perl-suid_5.6.1-8.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
