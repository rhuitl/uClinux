# This script was automatically generated from the dsa-1027
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A potential denial of service problem has been discovered in mailman,
the web-based GNU mailing list manager.  The (failing) parsing of
messages with malformed mime multiparts sometimes caused the whole
mailing list to become inoperative.
The old stable distribution (woody) is not vulnerable to this issue.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.5-8sarge2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your mailman package.


Solution : http://www.debian.org/security/2006/dsa-1027
Risk factor : High';

if (description) {
 script_id(22569);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1027");
 script_cve_id("CVE-2006-0052");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1027] DSA-1027-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1027-1 mailman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-8sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 3.1.\nUpgrade to mailman_2.1.5-8sarge2\n');
}
if (deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-8sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian sarge.\nUpgrade to mailman_2.1.5-8sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
