# This script was automatically generated from the dsa-1065
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Matteo Rosi and Leonardo Maccari discovered that hostapd, a wifi network
authenticator daemon, performs insufficient boundary checks on a key length
value, which might be exploited to crash the service.
The old stable distribution (woody) does not contain hostapd packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.3.7-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.5-1.
We recommend that you upgrade your hostapd package.


Solution : http://www.debian.org/security/2006/dsa-1065
Risk factor : High';

if (description) {
 script_id(22607);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1065");
 script_cve_id("CVE-2006-2213");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1065] DSA-1065-1 hostapd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1065-1 hostapd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hostapd', release: '', reference: '0.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostapd is vulnerable in Debian .\nUpgrade to hostapd_0.5-1\n');
}
if (deb_check(prefix: 'hostapd', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostapd is vulnerable in Debian 3.1.\nUpgrade to hostapd_0.3.7-2sarge1\n');
}
if (deb_check(prefix: 'hostapd', release: '3.1', reference: '0.3.7-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostapd is vulnerable in Debian sarge.\nUpgrade to hostapd_0.3.7-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
