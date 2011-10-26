# This script was automatically generated from the dsa-321
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
radiusd-cistron contains a bug allowing a buffer overflow when a long
NAS-Port attribute is received.  This could allow a remote attacker to
execute arbitrary code on the server with the privileges of the RADIUS daemon
(usually root).
For the stable distribution (woody) this problem has been fixed in
version 1.6.6-1woody1.
For the old stable distribution (potato), this problem will be fixed
in a later advisory.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your radiusd-cistron package.


Solution : http://www.debian.org/security/2003/dsa-321
Risk factor : High';

if (description) {
 script_id(15158);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "321");
 script_cve_id("CVE-2003-0450");
 script_bugtraq_id(7892);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA321] DSA-321-1 radiusd-cistron");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-321-1 radiusd-cistron");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'radiusd-cistron', release: '3.0', reference: '1.6.6-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package radiusd-cistron is vulnerable in Debian 3.0.\nUpgrade to radiusd-cistron_1.6.6-1woody1\n');
}
if (deb_check(prefix: 'radiusd-cistron', release: '3.0', reference: '1.6.6-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package radiusd-cistron is vulnerable in Debian woody.\nUpgrade to radiusd-cistron_1.6.6-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
