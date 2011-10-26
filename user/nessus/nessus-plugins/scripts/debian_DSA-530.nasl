# This script was automatically generated from the dsa-530
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Thomas Walpuski reported a buffer overflow in l2tpd, an implementation
of the layer 2 tunneling protocol, whereby a remote attacker could
potentially cause arbitrary code to be executed by transmitting a
specially crafted packet.  The exploitability of this vulnerability
has not been verified.
For the current stable distribution (woody), this problem has been
fixed in version 0.67-1.2.
For the unstable distribution (sid), this problem has been fixed in
version 0.70-pre20031121-2.
We recommend that you update your l2tpd package.


Solution : http://www.debian.org/security/2004/dsa-530
Risk factor : High';

if (description) {
 script_id(15367);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "530");
 script_cve_id("CVE-2004-0649");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA530] DSA-530-1 l2tpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-530-1 l2tpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'l2tpd', release: '3.0', reference: '0.67-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package l2tpd is vulnerable in Debian 3.0.\nUpgrade to l2tpd_0.67-1.2\n');
}
if (deb_check(prefix: 'l2tpd', release: '3.1', reference: '0.70-pre20031121-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package l2tpd is vulnerable in Debian 3.1.\nUpgrade to l2tpd_0.70-pre20031121-2\n');
}
if (deb_check(prefix: 'l2tpd', release: '3.0', reference: '0.67-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package l2tpd is vulnerable in Debian woody.\nUpgrade to l2tpd_0.67-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
