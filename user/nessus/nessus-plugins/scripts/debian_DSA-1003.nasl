# This script was automatically generated from the dsa-1003
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Eric Romang discovered that xpvm, a graphical console and monitor for
PVM, creates a temporary file that allows local attackers to create or
overwrite arbitrary files with the privileges of the user running
xpvm.
For the old stable distribution (woody) this problem has been fixed in
version 1.2.5-7.2woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.5-7.3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.5-8.
We recommend that you upgrade your xpvm package.


Solution : http://www.debian.org/security/2006/dsa-1003
Risk factor : High';

if (description) {
 script_id(22545);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1003");
 script_cve_id("CVE-2005-2240");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1003] DSA-1003-1 xpvm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1003-1 xpvm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpvm', release: '', reference: '1.2.5-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpvm is vulnerable in Debian .\nUpgrade to xpvm_1.2.5-8\n');
}
if (deb_check(prefix: 'xpvm', release: '3.0', reference: '1.2.5-7.2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpvm is vulnerable in Debian 3.0.\nUpgrade to xpvm_1.2.5-7.2woody1\n');
}
if (deb_check(prefix: 'xpvm', release: '3.1', reference: '1.2.5-7.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpvm is vulnerable in Debian 3.1.\nUpgrade to xpvm_1.2.5-7.3sarge1\n');
}
if (deb_check(prefix: 'xpvm', release: '3.1', reference: '1.2.5-7.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpvm is vulnerable in Debian sarge.\nUpgrade to xpvm_1.2.5-7.3sarge1\n');
}
if (deb_check(prefix: 'xpvm', release: '3.0', reference: '1.2.5-7.2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpvm is vulnerable in Debian woody.\nUpgrade to xpvm_1.2.5-7.2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
