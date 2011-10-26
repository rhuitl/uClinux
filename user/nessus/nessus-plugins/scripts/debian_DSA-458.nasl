# This script was automatically generated from the dsa-458
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
This security advisory corrects DSA 458-2 which caused a problem in
the gethostbyaddr routine.
The original advisory said:
Sebastian Schmidt discovered a buffer overflow bug in Python\'s
getaddrinfo function, which could allow an IPv6 address, supplied by a
remote attacker via DNS, to overwrite memory on the stack.
This bug only exists in python 2.2 and 2.2.1, and only when IPv6
support is disabled.  The python2.2 package in Debian woody meets
these conditions (the \'python\' package does not).
For the stable distribution (woody), this bug has been fixed in
version 2.2.1-4.6.
The testing and unstable distribution (sarge and sid) are not
affected by this problem.
We recommend that you update your python2.2 packages.


Solution : http://www.debian.org/security/2004/dsa-458
Risk factor : High';

if (description) {
 script_id(15295);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "458");
 script_cve_id("CVE-2004-0150");
 script_bugtraq_id(9836);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA458] DSA-458-3 python2.2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-458-3 python2.2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'idle-python2.2', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python2.2 is vulnerable in Debian 3.0.\nUpgrade to idle-python2.2_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2 is vulnerable in Debian 3.0.\nUpgrade to python2.2_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2-dev', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-dev is vulnerable in Debian 3.0.\nUpgrade to python2.2-dev_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2-doc', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-doc is vulnerable in Debian 3.0.\nUpgrade to python2.2-doc_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2-elisp', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-elisp is vulnerable in Debian 3.0.\nUpgrade to python2.2-elisp_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2-examples', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-examples is vulnerable in Debian 3.0.\nUpgrade to python2.2-examples_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2-gdbm', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-gdbm is vulnerable in Debian 3.0.\nUpgrade to python2.2-gdbm_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2-mpz', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-mpz is vulnerable in Debian 3.0.\nUpgrade to python2.2-mpz_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2-tk', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-tk is vulnerable in Debian 3.0.\nUpgrade to python2.2-tk_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2-xmlbase', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-xmlbase is vulnerable in Debian 3.0.\nUpgrade to python2.2-xmlbase_2.2.1-4.6\n');
}
if (deb_check(prefix: 'python2.2', release: '3.0', reference: '2.2.1-4.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2 is vulnerable in Debian woody.\nUpgrade to python2.2_2.2.1-4.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
