# This script was automatically generated from the dsa-414
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in jabber, an instant messaging server,
whereby a bug in the handling of SSL connections could cause the
server process to crash, resulting in a denial of service.
For the current stable distribution (woody) this problem has been
fixed in version 1.4.2a-1.1woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.4.3-1.
We recommend that you update your jabber package.


Solution : http://www.debian.org/security/2004/dsa-414
Risk factor : High';

if (description) {
 script_id(15251);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "414");
 script_cve_id("CVE-2004-0013");
 script_bugtraq_id(9376);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA414] DSA-414-1 jabber");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-414-1 jabber");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'jabber', release: '3.0', reference: '1.4.2a-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package jabber is vulnerable in Debian 3.0.\nUpgrade to jabber_1.4.2a-1.1woody1\n');
}
if (deb_check(prefix: 'jabber', release: '3.1', reference: '1.4.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package jabber is vulnerable in Debian 3.1.\nUpgrade to jabber_1.4.3-1\n');
}
if (deb_check(prefix: 'jabber', release: '3.0', reference: '1.4.2a-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package jabber is vulnerable in Debian woody.\nUpgrade to jabber_1.4.2a-1.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
