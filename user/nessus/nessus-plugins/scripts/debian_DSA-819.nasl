# This script was automatically generated from the dsa-819
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
version 2.1.3-3.4.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.3dfsg-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.1.3dfsg-3.
We recommend that you upgrade your python2.1 packages.


Solution : http://www.debian.org/security/2005/dsa-819
Risk factor : High';

if (description) {
 script_id(19788);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "819");
 script_cve_id("CVE-2005-2491");
 script_bugtraq_id(14620);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA819] DSA-819-1 python2.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-819-1 python2.1");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'python2.1', release: '', reference: '2.1.3dfsg-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1 is vulnerable in Debian .\nUpgrade to python2.1_2.1.3dfsg-3\n');
}
if (deb_check(prefix: 'idle', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle is vulnerable in Debian 3.0.\nUpgrade to idle_2.1.3-3.4\n');
}
if (deb_check(prefix: 'idle-python2.1', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python2.1 is vulnerable in Debian 3.0.\nUpgrade to idle-python2.1_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python is vulnerable in Debian 3.0.\nUpgrade to python_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python-dev', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-dev is vulnerable in Debian 3.0.\nUpgrade to python-dev_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python-doc', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-doc is vulnerable in Debian 3.0.\nUpgrade to python-doc_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python-elisp', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-elisp is vulnerable in Debian 3.0.\nUpgrade to python-elisp_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python-examples', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-examples is vulnerable in Debian 3.0.\nUpgrade to python-examples_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python-gdbm', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-gdbm is vulnerable in Debian 3.0.\nUpgrade to python-gdbm_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python-mpz', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-mpz is vulnerable in Debian 3.0.\nUpgrade to python-mpz_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python-tk', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-tk is vulnerable in Debian 3.0.\nUpgrade to python-tk_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python-xmlbase', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-xmlbase is vulnerable in Debian 3.0.\nUpgrade to python-xmlbase_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1 is vulnerable in Debian 3.0.\nUpgrade to python2.1_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1-dev', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-dev is vulnerable in Debian 3.0.\nUpgrade to python2.1-dev_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1-doc', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-doc is vulnerable in Debian 3.0.\nUpgrade to python2.1-doc_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1-elisp', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-elisp is vulnerable in Debian 3.0.\nUpgrade to python2.1-elisp_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1-examples', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-examples is vulnerable in Debian 3.0.\nUpgrade to python2.1-examples_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1-gdbm', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-gdbm is vulnerable in Debian 3.0.\nUpgrade to python2.1-gdbm_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1-mpz', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-mpz is vulnerable in Debian 3.0.\nUpgrade to python2.1-mpz_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1-tk', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-tk is vulnerable in Debian 3.0.\nUpgrade to python2.1-tk_2.1.3-3.4\n');
}
if (deb_check(prefix: 'python2.1-xmlbase', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-xmlbase is vulnerable in Debian 3.0.\nUpgrade to python2.1-xmlbase_2.1.3-3.4\n');
}
if (deb_check(prefix: 'idle-python2.1', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python2.1 is vulnerable in Debian 3.1.\nUpgrade to idle-python2.1_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1 is vulnerable in Debian 3.1.\nUpgrade to python2.1_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1-dev', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-dev is vulnerable in Debian 3.1.\nUpgrade to python2.1-dev_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1-doc', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-doc is vulnerable in Debian 3.1.\nUpgrade to python2.1-doc_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1-examples', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-examples is vulnerable in Debian 3.1.\nUpgrade to python2.1-examples_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1-gdbm', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-gdbm is vulnerable in Debian 3.1.\nUpgrade to python2.1-gdbm_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1-mpz', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-mpz is vulnerable in Debian 3.1.\nUpgrade to python2.1-mpz_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1-tk', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-tk is vulnerable in Debian 3.1.\nUpgrade to python2.1-tk_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1-xmlbase', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-xmlbase is vulnerable in Debian 3.1.\nUpgrade to python2.1-xmlbase_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1', release: '3.1', reference: '2.1.3dfsg-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1 is vulnerable in Debian sarge.\nUpgrade to python2.1_2.1.3dfsg-1sarge1\n');
}
if (deb_check(prefix: 'python2.1', release: '3.0', reference: '2.1.3-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1 is vulnerable in Debian woody.\nUpgrade to python2.1_2.1.3-3.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
