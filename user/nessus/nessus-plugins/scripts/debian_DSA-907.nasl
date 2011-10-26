# This script was automatically generated from the dsa-907
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Akira Yoshiyama noticed that ipmenu, an cursel iptables/iproute2 GUI,
creates a temporary file in an insecure fashion allowing a local
attacker to overwrite arbitrary files utilising a symlink attack.
For the old stable distribution (woody) this problem has been fixed in
version 0.0.3-4woody1
The stable distribution (sarge) does not contain the ipmenu package.
For the unstable distribution (sid) this problem has been fixed in
version 0.0.3-5.
We recommend that you upgrade your ipmenu package.


Solution : http://www.debian.org/security/2005/dsa-907
Risk factor : High';

if (description) {
 script_id(22773);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "907");
 script_cve_id("CVE-2004-2569");
 script_bugtraq_id(10269);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA907] DSA-907-1 ipmenu");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-907-1 ipmenu");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ipmenu', release: '3.0', reference: '0.0.3-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipmenu is vulnerable in Debian 3.0.\nUpgrade to ipmenu_0.0.3-4woody1\n');
}
if (deb_check(prefix: 'ipmenu', release: '3.1', reference: '0.0.3-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipmenu is vulnerable in Debian 3.1.\nUpgrade to ipmenu_0.0.3-5\n');
}
if (deb_check(prefix: 'ipmenu', release: '3.0', reference: '0.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipmenu is vulnerable in Debian woody.\nUpgrade to ipmenu_0.0\n');
}
if (w) { security_hole(port: 0, data: desc); }
