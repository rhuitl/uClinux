# This script was automatically generated from the dsa-792
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler discovered that pstotext, a utility to extract text from
PostScript and PDF files, did not execute ghostscript with the -dSAFER
argument, which prevents potential malicious operations to happen.
For the old stable distribution (woody) this problem has been fixed in
version 1.8g-5woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.9-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.9-2.
We recommend that you upgrade your pstotext package.


Solution : http://www.debian.org/security/2005/dsa-792
Risk factor : High';

if (description) {
 script_id(19562);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "792");
 script_cve_id("CVE-2005-2536");
 script_bugtraq_id(14378);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA792] DSA-792-1 pstotext");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-792-1 pstotext");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pstotext', release: '', reference: '1.9-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pstotext is vulnerable in Debian .\nUpgrade to pstotext_1.9-2\n');
}
if (deb_check(prefix: 'pstotext', release: '3.0', reference: '1.8g-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pstotext is vulnerable in Debian 3.0.\nUpgrade to pstotext_1.8g-5woody1\n');
}
if (deb_check(prefix: 'pstotext', release: '3.1', reference: '1.9-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pstotext is vulnerable in Debian 3.1.\nUpgrade to pstotext_1.9-1sarge1\n');
}
if (deb_check(prefix: 'pstotext', release: '3.1', reference: '1.9-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pstotext is vulnerable in Debian sarge.\nUpgrade to pstotext_1.9-1sarge1\n');
}
if (deb_check(prefix: 'pstotext', release: '3.0', reference: '1.8g-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pstotext is vulnerable in Debian woody.\nUpgrade to pstotext_1.8g-5woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
