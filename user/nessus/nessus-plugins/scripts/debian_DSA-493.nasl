# This script was automatically generated from the dsa-493
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in the Socks-5 proxy code of
XChat, an IRC client for X similar to AmIRC.  This allows an attacker
to execute arbitrary code on the users\' machine.
For the stable distribution (woody) this problem has been fixed in
version 1.8.9-0woody3.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.8-1.
We recommend that you upgrade your xchat and related packages.


Solution : http://www.debian.org/security/2004/dsa-493
Risk factor : High';

if (description) {
 script_id(15330);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "493");
 script_cve_id("CVE-2004-0409");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA493] DSA-493-1 xchat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-493-1 xchat");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xchat', release: '3.0', reference: '1.8.9-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xchat is vulnerable in Debian 3.0.\nUpgrade to xchat_1.8.9-0woody3\n');
}
if (deb_check(prefix: 'xchat-common', release: '3.0', reference: '1.8.9-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xchat-common is vulnerable in Debian 3.0.\nUpgrade to xchat-common_1.8.9-0woody3\n');
}
if (deb_check(prefix: 'xchat-gnome', release: '3.0', reference: '1.8.9-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xchat-gnome is vulnerable in Debian 3.0.\nUpgrade to xchat-gnome_1.8.9-0woody3\n');
}
if (deb_check(prefix: 'xchat-text', release: '3.0', reference: '1.8.9-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xchat-text is vulnerable in Debian 3.0.\nUpgrade to xchat-text_1.8.9-0woody3\n');
}
if (deb_check(prefix: 'xchat', release: '3.1', reference: '2.0.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xchat is vulnerable in Debian 3.1.\nUpgrade to xchat_2.0.8-1\n');
}
if (deb_check(prefix: 'xchat', release: '3.0', reference: '1.8.9-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xchat is vulnerable in Debian woody.\nUpgrade to xchat_1.8.9-0woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
