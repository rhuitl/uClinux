# This script was automatically generated from the dsa-018
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'PkC have found a heap overflow in tinyproxy that could be remotely exploited.  An attacker could gain a shell (user nobody) remotely.

We recommend you upgrade your tinyproxy package immediately.


Solution : http://www.debian.org/security/2001/dsa-018
Risk factor : High';

if (description) {
 script_id(14855);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "018");
 script_cve_id("CVE-2001-0129");
 script_bugtraq_id(2217);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA018] DSA-018-1 tinyproxy");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-018-1 tinyproxy");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tinyproxy', release: '2.2', reference: '1.3.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tinyproxy is vulnerable in Debian 2.2.\nUpgrade to tinyproxy_1.3.1-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
