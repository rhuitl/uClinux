# This script was automatically generated from the dsa-376
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow exists in exim, which is the standard mail transport
agent in Debian.  By supplying a specially crafted HELO or EHLO
command, an attacker could cause a constant string to be written past
the end of a buffer allocated on the heap.  This vulnerability is not
believed at this time to be exploitable to execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
exim version 3.35-1woody2 and exim-tls version 3.35-3woody1.
For the unstable distribution (sid) this problem has been fixed in
exim version 3.36-8.  The unstable distribution does not contain an
exim-tls package.
We recommend that you update your exim or exim-tls package.


Solution : http://www.debian.org/security/2003/dsa-376
Risk factor : High';

if (description) {
 script_id(15213);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "376");
 script_cve_id("CVE-2003-0743");
 script_bugtraq_id(8518);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA376] DSA-376-2 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-376-2 exim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'exim', release: '3.0', reference: '3.35-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian 3.0.\nUpgrade to exim_3.35-1woody2\n');
}
if (deb_check(prefix: 'exim-tls', release: '3.0', reference: '3.35-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim-tls is vulnerable in Debian 3.0.\nUpgrade to exim-tls_3.35-3woody1\n');
}
if (deb_check(prefix: 'eximon', release: '3.0', reference: '3.35-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eximon is vulnerable in Debian 3.0.\nUpgrade to eximon_3.35-1woody2\n');
}
if (deb_check(prefix: 'exim', release: '3.1', reference: '3.36-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian 3.1.\nUpgrade to exim_3.36-8\n');
}
if (deb_check(prefix: 'exim', release: '3.0', reference: '3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian woody.\nUpgrade to exim_3\n');
}
if (w) { security_hole(port: 0, data: desc); }
