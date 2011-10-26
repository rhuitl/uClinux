# This script was automatically generated from the dsa-081
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
In SNS Advisory No. 32 a buffer overflow vulnerability has been
reported in the routine which parses MIME headers that are returned
from web servers.  A malicious web server administrator could exploit
this and let the client web browser execute arbitrary code.
w3m handles MIME headers included in the request/response message of
HTTP communication like any other web browser.  A buffer overflow will
occur when w3m receives a MIME encoded header with base64 format.
This problem has been fixed by the maintainer in version
0.1.10+0.1.11pre+kokb23-4 of w3m and w3m-ssl (for the SSL-enabled
version), both for Debian GNU/Linux 2.2.
We recommend that you upgrade your w3m packages immediately.


Solution : http://www.debian.org/security/2001/dsa-081
Risk factor : High';

if (description) {
 script_id(14918);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "081");
 script_cve_id("CVE-2001-0700");
 script_bugtraq_id(2895);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA081] DSA-081-1 w3m");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-081-1 w3m");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'w3m', release: '2.2', reference: '0.1.10+0.1.11pre+kokb23-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package w3m is vulnerable in Debian 2.2.\nUpgrade to w3m_0.1.10+0.1.11pre+kokb23-4\n');
}
if (deb_check(prefix: 'w3m-ssl', release: '2.2', reference: '0.1.10+0.1.11pre+kokb23-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package w3m-ssl is vulnerable in Debian 2.2.\nUpgrade to w3m-ssl_0.1.10+0.1.11pre+kokb23-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
