# This script was automatically generated from the dsa-1152
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Felix Wiemann discovered that trac, an enhanced Wiki and issue
tracking system for software development projects, can be used to
disclose arbitrary local files.  To fix this problem, python-docutils
needs to be updated as well.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.1-3sarge5 of trac and version 0.3.7-2sarge1 of
python-docutils.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.6-1.
We recommend that you upgrade your trac and python-docutils packages.


Solution : http://www.debian.org/security/2006/dsa-1152
Risk factor : High';

if (description) {
 script_id(22694);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1152");
 script_cve_id("CVE-2006-3695");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1152] DSA-1152-1 trac");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1152-1 trac");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'trac', release: '', reference: '0.9.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian .\nUpgrade to trac_0.9.6-1\n');
}
if (deb_check(prefix: 'python-docutils', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-docutils is vulnerable in Debian 3.1.\nUpgrade to python-docutils_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'python-roman', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-roman is vulnerable in Debian 3.1.\nUpgrade to python-roman_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'python2.1-difflib', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-difflib is vulnerable in Debian 3.1.\nUpgrade to python2.1-difflib_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'python2.1-textwrap', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-textwrap is vulnerable in Debian 3.1.\nUpgrade to python2.1-textwrap_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-docutils', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-docutils is vulnerable in Debian 3.1.\nUpgrade to python2.2-docutils_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'python2.2-textwrap', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-textwrap is vulnerable in Debian 3.1.\nUpgrade to python2.2-textwrap_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'python2.3-docutils', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.3-docutils is vulnerable in Debian 3.1.\nUpgrade to python2.3-docutils_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'python2.4-docutils', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-docutils is vulnerable in Debian 3.1.\nUpgrade to python2.4-docutils_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'trac', release: '3.1', reference: '0.8.1-3sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian 3.1.\nUpgrade to trac_0.8.1-3sarge5\n');
}
if (deb_check(prefix: 'trac', release: '3.1', reference: '0.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian sarge.\nUpgrade to trac_0.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
