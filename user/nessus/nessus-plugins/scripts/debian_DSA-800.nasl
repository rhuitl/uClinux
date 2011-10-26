# This script was automatically generated from the dsa-800
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An integer overflow with subsequent buffer overflow has been detected
in PCRE, the Perl Compatible Regular Expressions library, which allows
an attacker to execute arbitrary code.
Since several packages link dynamically to this library you are
advised to restart the corresponding services or programs
respectively.  The command &ldquo;apt-cache showpkg libpcre3&rdquo; will list
the corresponding packages in the "Reverse Depends:" section.
For the old stable distribution (woody) this problem has been fixed in
version 3.4-1.1woody1.
For the stable distribution (sarge) this problem has been fixed in
version 4.5-1.2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 6.3-1.
We recommend that you upgrade your libpcre3 package.


Solution : http://www.debian.org/security/2005/dsa-800
Risk factor : High';

if (description) {
 script_id(19570);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "800");
 script_cve_id("CVE-2005-2491");
 script_bugtraq_id(14620);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA800] DSA-800-1 pcre3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-800-1 pcre3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pcre3', release: '', reference: '6.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcre3 is vulnerable in Debian .\nUpgrade to pcre3_6.3-1\n');
}
if (deb_check(prefix: 'libpcre3', release: '3.0', reference: '3.4-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpcre3 is vulnerable in Debian 3.0.\nUpgrade to libpcre3_3.4-1.1woody1\n');
}
if (deb_check(prefix: 'libpcre3-dev', release: '3.0', reference: '3.4-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpcre3-dev is vulnerable in Debian 3.0.\nUpgrade to libpcre3-dev_3.4-1.1woody1\n');
}
if (deb_check(prefix: 'pgrep', release: '3.0', reference: '3.4-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pgrep is vulnerable in Debian 3.0.\nUpgrade to pgrep_3.4-1.1woody1\n');
}
if (deb_check(prefix: 'libpcre3', release: '3.1', reference: '4.5-1.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpcre3 is vulnerable in Debian 3.1.\nUpgrade to libpcre3_4.5-1.2sarge1\n');
}
if (deb_check(prefix: 'libpcre3-dev', release: '3.1', reference: '4.5-1.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpcre3-dev is vulnerable in Debian 3.1.\nUpgrade to libpcre3-dev_4.5-1.2sarge1\n');
}
if (deb_check(prefix: 'pcregrep', release: '3.1', reference: '4.5-1.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcregrep is vulnerable in Debian 3.1.\nUpgrade to pcregrep_4.5-1.2sarge1\n');
}
if (deb_check(prefix: 'pgrep', release: '3.1', reference: '4.5-1.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pgrep is vulnerable in Debian 3.1.\nUpgrade to pgrep_4.5-1.2sarge1\n');
}
if (deb_check(prefix: 'pcre3', release: '3.1', reference: '4.5-1.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcre3 is vulnerable in Debian sarge.\nUpgrade to pcre3_4.5-1.2sarge1\n');
}
if (deb_check(prefix: 'pcre3', release: '3.0', reference: '3.4-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcre3 is vulnerable in Debian woody.\nUpgrade to pcre3_3.4-1.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
