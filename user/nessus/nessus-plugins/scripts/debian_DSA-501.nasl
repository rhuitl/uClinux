# This script was automatically generated from the dsa-501
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Georgi Guninski discovered two stack-based buffer overflows.  They can
not be exploited with the default configuration from the Debian
system, though.  The Common Vulnerabilities and Exposures project
identifies the following problems that are fixed with this update:
    When "sender_verify = true" is configured in exim.conf a buffer
    overflow can happen during verification of the sender.  This
    problem is fixed in exim 4.
    When headers_check_syntax is configured in exim.conf a buffer
    overflow can happen during the header check.  This problem does
    also exist in exim 4.
For the stable distribution (woody) these problems have been fixed in
version 3.35-1woody3.
For the unstable distribution (sid) these problems have been fixed in
version 3.36-11 for exim 3 and in version 4.33-1 for exim 4.
We recommend that you upgrade your exim package.


Solution : http://www.debian.org/security/2004/dsa-501
Risk factor : High';

if (description) {
 script_id(15338);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "501");
 script_cve_id("CVE-2004-0399", "CVE-2004-0400");
 script_bugtraq_id(10290, 10291);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA501] DSA-501-1 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-501-1 exim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'exim', release: '3.0', reference: '3.35-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian 3.0.\nUpgrade to exim_3.35-1woody3\n');
}
if (deb_check(prefix: 'eximon', release: '3.0', reference: '3.35-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eximon is vulnerable in Debian 3.0.\nUpgrade to eximon_3.35-1woody3\n');
}
if (deb_check(prefix: 'exim', release: '3.1', reference: '3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian 3.1.\nUpgrade to exim_3\n');
}
if (deb_check(prefix: 'exim', release: '3.0', reference: '3.35-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian woody.\nUpgrade to exim_3.35-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
