# This script was automatically generated from the dsa-436
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been fixed in the mailman package:
The cross-site scripting vulnerabilities could allow an attacker to
perform administrative operations without authorization, by stealing a
session cookie.
For the current stable distribution (woody) these problems have been
fixed in version 2.0.11-1woody7.
For the unstable distribution (sid),
CVE-2003-0965 is fixed in version 2.1.4-1, and
CVE-2003-0038 in version 2.1.1-1.
CVE-2003-0991 will be fixed soon.
We recommend that you update your mailman package.


Solution : http://www.debian.org/security/2004/dsa-436
Risk factor : High';

if (description) {
 script_id(15273);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "436");
 script_cve_id("CVE-2003-0038", "CVE-2003-0965", "CVE-2003-0991");
 script_bugtraq_id(9336, 9620);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA436] DSA-436-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-436-1 mailman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailman', release: '3.0', reference: '2.0.11-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 3.0.\nUpgrade to mailman_2.0.11-1woody8\n');
}
if (deb_check(prefix: 'mailman', release: '3.1', reference: '2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 3.1.\nUpgrade to mailman_2.1\n');
}
if (deb_check(prefix: 'mailman', release: '3.0', reference: '2.0.11-1woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian woody.\nUpgrade to mailman_2.0.11-1woody7\n');
}
if (w) { security_hole(port: 0, data: desc); }
