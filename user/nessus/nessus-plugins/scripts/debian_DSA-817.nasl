# This script was automatically generated from the dsa-817
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An integer overflow with a subsequent buffer overflow has been detected
in PCRE, the Perl Compatible Regular Expressions library, which allows
an attacker to execute arbitrary code, and is also present in Python.
Exploiting this vulnerability requires an attacker to specify the used
regular expression.
For the old stable distribution (woody) this problem has been fixed in
version 2.2.1-4.8.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.3dfsg-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.2.3dfsg-4.
We recommend that you upgrade your python2.2 packages.


Solution : http://www.debian.org/security/2005/dsa-817
Risk factor : High';

if (description) {
 script_id(19786);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "817");
 script_cve_id("CVE-2005-2491");
 script_bugtraq_id(14620);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA817] DSA-817-1 python2.2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-817-1 python2.2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'python2.2', release: '', reference: '2.2.3dfsg-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2 is vulnerable in Debian .\nUpgrade to python2.2_2.2.3dfsg-4\n');
}
if (deb_check(prefix: 'idle-python2.2', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python2.2 is vulnerable in Debian 3.0.\nUpgrade to idle-python2.2_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2 is vulnerable in Debian 3.0.\nUpgrade to python2.2_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2-dev', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-dev is vulnerable in Debian 3.0.\nUpgrade to python2.2-dev_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2-doc', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-doc is vulnerable in Debian 3.0.\nUpgrade to python2.2-doc_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2-elisp', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-elisp is vulnerable in Debian 3.0.\nUpgrade to python2.2-elisp_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2-examples', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-examples is vulnerable in Debian 3.0.\nUpgrade to python2.2-examples_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2-gdbm', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-gdbm is vulnerable in Debian 3.0.\nUpgrade to python2.2-gdbm_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2-mpz', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-mpz is vulnerable in Debian 3.0.\nUpgrade to python2.2-mpz_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2-tk', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-tk is vulnerable in Debian 3.0.\nUpgrade to python2.2-tk_2.2.1-4.8\n');
}
if (deb_check(prefix: 'python2.2-xmlbase', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-xmlbase is vulnerable in Debian 3.0.\nUpgrade to python2.2-xmlbase_2.2.1-4.8\n');
}
if (deb_check(prefix: 'idle-python2.2', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python2.2 is vulnerable in Debian 3.1.\nUpgrade to idle-python2.2_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2 is vulnerable in Debian 3.1.\nUpgrade to python2.2_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-dev', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-dev is vulnerable in Debian 3.1.\nUpgrade to python2.2-dev_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-doc', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-doc is vulnerable in Debian 3.1.\nUpgrade to python2.2-doc_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-examples', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-examples is vulnerable in Debian 3.1.\nUpgrade to python2.2-examples_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-gdbm', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-gdbm is vulnerable in Debian 3.1.\nUpgrade to python2.2-gdbm_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-mpz', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-mpz is vulnerable in Debian 3.1.\nUpgrade to python2.2-mpz_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-tk', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-tk is vulnerable in Debian 3.1.\nUpgrade to python2.2-tk_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-xmlbase', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-xmlbase is vulnerable in Debian 3.1.\nUpgrade to python2.2-xmlbase_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2', release: '3.1', reference: '2.2.3dfsg-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2 is vulnerable in Debian sarge.\nUpgrade to python2.2_2.2.3dfsg-2sarge1\n');
}
if (deb_check(prefix: 'python2.2', release: '3.0', reference: '2.2.1-4.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2 is vulnerable in Debian woody.\nUpgrade to python2.2_2.2.1-4.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
