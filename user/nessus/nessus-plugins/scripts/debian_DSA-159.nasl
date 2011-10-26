# This script was automatically generated from the dsa-159
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Zack Weinberg discovered an insecure use of a temporary file in
os._execvpe from os.py.  It uses a predictable name which could lead
execution of arbitrary code.
This problem has been fixed in several versions of Python: For the
current stable distribution (woody) it has been fixed in version
1.5.2-23.1 of Python 1.5, in version 2.1.3-3.1 of Python 2.1 and in
version 2.2.1-4.1 of Python 2.2.  For the old stable distribution
(potato) this has been fixed in version 1.5.2-10potato12 for Python
1.5.  For the unstable distribution (sid) this has been fixed in
version 1.5.2-24 of Python 1.5, in version 2.1.3-6a of Python 2.1 and
in version 2.2.1-8 of Python 2.2.  Python 2.3 is not affected by this
problem.
We recommend that you upgrade your Python packages immediately.


Solution : http://www.debian.org/security/2002/dsa-159
Risk factor : High';

if (description) {
 script_id(14996);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "159");
 script_cve_id("CVE-2002-1119");
 script_bugtraq_id(5581);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA159] DSA-159-1 python");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-159-1 python");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'idle', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle is vulnerable in Debian 2.2.\nUpgrade to idle_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-base', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-base is vulnerable in Debian 2.2.\nUpgrade to python-base_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-dev', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-dev is vulnerable in Debian 2.2.\nUpgrade to python-dev_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-elisp', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-elisp is vulnerable in Debian 2.2.\nUpgrade to python-elisp_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-examples', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-examples is vulnerable in Debian 2.2.\nUpgrade to python-examples_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-gdbm', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-gdbm is vulnerable in Debian 2.2.\nUpgrade to python-gdbm_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-mpz', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-mpz is vulnerable in Debian 2.2.\nUpgrade to python-mpz_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-regrtest', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-regrtest is vulnerable in Debian 2.2.\nUpgrade to python-regrtest_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-tk', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-tk is vulnerable in Debian 2.2.\nUpgrade to python-tk_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'python-zlib', release: '2.2', reference: '1.5.2-10potato13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-zlib is vulnerable in Debian 2.2.\nUpgrade to python-zlib_1.5.2-10potato13\n');
}
if (deb_check(prefix: 'idle', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle is vulnerable in Debian 3.0.\nUpgrade to idle_2.1.3-3.2\n');
}
if (deb_check(prefix: 'idle-python1.5', release: '3.0', reference: '1.5.2-23.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python1.5 is vulnerable in Debian 3.0.\nUpgrade to idle-python1.5_1.5.2-23.2\n');
}
if (deb_check(prefix: 'idle-python2.1', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python2.1 is vulnerable in Debian 3.0.\nUpgrade to idle-python2.1_2.1.3-3.2\n');
}
if (deb_check(prefix: 'idle-python2.2', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python2.2 is vulnerable in Debian 3.0.\nUpgrade to idle-python2.2_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python is vulnerable in Debian 3.0.\nUpgrade to python_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python-dev', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-dev is vulnerable in Debian 3.0.\nUpgrade to python-dev_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python-doc', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-doc is vulnerable in Debian 3.0.\nUpgrade to python-doc_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python-elisp', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-elisp is vulnerable in Debian 3.0.\nUpgrade to python-elisp_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python-examples', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-examples is vulnerable in Debian 3.0.\nUpgrade to python-examples_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python-gdbm', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-gdbm is vulnerable in Debian 3.0.\nUpgrade to python-gdbm_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python-mpz', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-mpz is vulnerable in Debian 3.0.\nUpgrade to python-mpz_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python-tk', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-tk is vulnerable in Debian 3.0.\nUpgrade to python-tk_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python-xmlbase', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-xmlbase is vulnerable in Debian 3.0.\nUpgrade to python-xmlbase_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python1.5', release: '3.0', reference: '1.5.2-23.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python1.5 is vulnerable in Debian 3.0.\nUpgrade to python1.5_1.5.2-23.2\n');
}
if (deb_check(prefix: 'python1.5-dev', release: '3.0', reference: '1.5.2-23.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python1.5-dev is vulnerable in Debian 3.0.\nUpgrade to python1.5-dev_1.5.2-23.2\n');
}
if (deb_check(prefix: 'python1.5-examples', release: '3.0', reference: '1.5.2-23.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python1.5-examples is vulnerable in Debian 3.0.\nUpgrade to python1.5-examples_1.5.2-23.2\n');
}
if (deb_check(prefix: 'python1.5-gdbm', release: '3.0', reference: '1.5.2-23.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python1.5-gdbm is vulnerable in Debian 3.0.\nUpgrade to python1.5-gdbm_1.5.2-23.2\n');
}
if (deb_check(prefix: 'python1.5-mpz', release: '3.0', reference: '1.5.2-23.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python1.5-mpz is vulnerable in Debian 3.0.\nUpgrade to python1.5-mpz_1.5.2-23.2\n');
}
if (deb_check(prefix: 'python1.5-tk', release: '3.0', reference: '1.5.2-23.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python1.5-tk is vulnerable in Debian 3.0.\nUpgrade to python1.5-tk_1.5.2-23.2\n');
}
if (deb_check(prefix: 'python2.1', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1 is vulnerable in Debian 3.0.\nUpgrade to python2.1_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.1-dev', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-dev is vulnerable in Debian 3.0.\nUpgrade to python2.1-dev_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.1-doc', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-doc is vulnerable in Debian 3.0.\nUpgrade to python2.1-doc_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.1-elisp', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-elisp is vulnerable in Debian 3.0.\nUpgrade to python2.1-elisp_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.1-examples', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-examples is vulnerable in Debian 3.0.\nUpgrade to python2.1-examples_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.1-gdbm', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-gdbm is vulnerable in Debian 3.0.\nUpgrade to python2.1-gdbm_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.1-mpz', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-mpz is vulnerable in Debian 3.0.\nUpgrade to python2.1-mpz_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.1-tk', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-tk is vulnerable in Debian 3.0.\nUpgrade to python2.1-tk_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.1-xmlbase', release: '3.0', reference: '2.1.3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-xmlbase is vulnerable in Debian 3.0.\nUpgrade to python2.1-xmlbase_2.1.3-3.2\n');
}
if (deb_check(prefix: 'python2.2', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2 is vulnerable in Debian 3.0.\nUpgrade to python2.2_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python2.2-dev', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-dev is vulnerable in Debian 3.0.\nUpgrade to python2.2-dev_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python2.2-doc', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-doc is vulnerable in Debian 3.0.\nUpgrade to python2.2-doc_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python2.2-elisp', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-elisp is vulnerable in Debian 3.0.\nUpgrade to python2.2-elisp_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python2.2-examples', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-examples is vulnerable in Debian 3.0.\nUpgrade to python2.2-examples_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python2.2-gdbm', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-gdbm is vulnerable in Debian 3.0.\nUpgrade to python2.2-gdbm_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python2.2-mpz', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-mpz is vulnerable in Debian 3.0.\nUpgrade to python2.2-mpz_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python2.2-tk', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-tk is vulnerable in Debian 3.0.\nUpgrade to python2.2-tk_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python2.2-xmlbase', release: '3.0', reference: '2.2.1-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-xmlbase is vulnerable in Debian 3.0.\nUpgrade to python2.2-xmlbase_2.2.1-4.2\n');
}
if (deb_check(prefix: 'python', release: '3.1', reference: '1.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python is vulnerable in Debian 3.1.\nUpgrade to python_1.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
