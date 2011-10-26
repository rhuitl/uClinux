# This script was automatically generated from the dsa-211
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Rüdiger Kuhlmann, upstream developer of mICQ, a text based ICQ client,
discovered a problem in mICQ.  Receiving certain ICQ message types
that do not contain the required 0xFE separator causes all versions to
crash.
For the current stable distribution (woody) this problem has been
fixed in version 0.4.9-0woody3.
For the old stable distribution (potato) this problem has been fixed
in version 0.4.3-4.1.
For the unstable distribution (sid) this problem has been
fixed in version 0.4.9.4-1.
We recommend that you upgrade your micq package.


Solution : http://www.debian.org/security/2002/dsa-211
Risk factor : High';

if (description) {
 script_id(15048);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "211");
 script_cve_id("CVE-2002-1362");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA211] DSA-211-1 micq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-211-1 micq");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'micq', release: '2.2', reference: '0.4.3-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package micq is vulnerable in Debian 2.2.\nUpgrade to micq_0.4.3-4.1\n');
}
if (deb_check(prefix: 'micq', release: '3.0', reference: '0.4.9-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package micq is vulnerable in Debian 3.0.\nUpgrade to micq_0.4.9-0woody3\n');
}
if (deb_check(prefix: 'micq', release: '3.1', reference: '0.4.9.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package micq is vulnerable in Debian 3.1.\nUpgrade to micq_0.4.9.4-1\n');
}
if (deb_check(prefix: 'micq', release: '2.2', reference: '0.4.3-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package micq is vulnerable in Debian potato.\nUpgrade to micq_0.4.3-4.1\n');
}
if (deb_check(prefix: 'micq', release: '3.0', reference: '0.4.9-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package micq is vulnerable in Debian woody.\nUpgrade to micq_0.4.9-0woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
