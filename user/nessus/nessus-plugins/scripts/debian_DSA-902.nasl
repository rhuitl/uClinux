# This script was automatically generated from the dsa-902
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in the sendmail program of
xmail, an advanced, fast and reliable ESMTP/POP3 mail server that
could lead to the execution of arbitrary code with group mail
privileges.
The old stable distribution (woody) does not contain xmail packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.21-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.22-1.
We recommend that you upgrade your xmail package.


Solution : http://www.debian.org/security/2005/dsa-902
Risk factor : High';

if (description) {
 script_id(22768);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "902");
 script_cve_id("CVE-2005-2943");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA902] DSA-902-1 xmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-902-1 xmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xmail', release: '', reference: '1.22-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmail is vulnerable in Debian .\nUpgrade to xmail_1.22-1\n');
}
if (deb_check(prefix: 'xmail', release: '3.1', reference: '1.21-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmail is vulnerable in Debian 3.1.\nUpgrade to xmail_1.21-3sarge1\n');
}
if (deb_check(prefix: 'xmail-doc', release: '3.1', reference: '1.21-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmail-doc is vulnerable in Debian 3.1.\nUpgrade to xmail-doc_1.21-3sarge1\n');
}
if (deb_check(prefix: 'xmail', release: '3.1', reference: '1.21-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmail is vulnerable in Debian sarge.\nUpgrade to xmail_1.21-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
