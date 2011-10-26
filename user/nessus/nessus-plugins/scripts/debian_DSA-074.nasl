# This script was automatically generated from the dsa-074
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Alban Hertroys found a buffer overflow in Window Maker (a popular window
manager for X). The code that handles titles in the window list menu did
not check the length of the title when copying it to a buffer. Since
applications will set the title using data that can\'t be trusted (for
example, most web browsers will include the title of the web page being
shown in the title of their window), this could be exploited remotely.

This has been fixed in version 0.61.1-4.1 of the Debian package, and
upstream version 0.65.1.  We recommend that you update your Window
Maker package immediately. 



Solution : http://www.debian.org/security/2001/dsa-074
Risk factor : High';

if (description) {
 script_id(14911);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "074");
 script_cve_id("CVE-2001-1027");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA074] DSA-074-1 wmaker");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-074-1 wmaker");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libdockapp-dev', release: '2.2', reference: '0.61.1-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdockapp-dev is vulnerable in Debian 2.2.\nUpgrade to libdockapp-dev_0.61.1-4.1\n');
}
if (deb_check(prefix: 'libwings-dev', release: '2.2', reference: '0.61.1-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwings-dev is vulnerable in Debian 2.2.\nUpgrade to libwings-dev_0.61.1-4.1\n');
}
if (deb_check(prefix: 'libwmaker0-dev', release: '2.2', reference: '0.61.1-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwmaker0-dev is vulnerable in Debian 2.2.\nUpgrade to libwmaker0-dev_0.61.1-4.1\n');
}
if (deb_check(prefix: 'libwraster1', release: '2.2', reference: '0.61.1-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwraster1 is vulnerable in Debian 2.2.\nUpgrade to libwraster1_0.61.1-4.1\n');
}
if (deb_check(prefix: 'libwraster1-dev', release: '2.2', reference: '0.61.1-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwraster1-dev is vulnerable in Debian 2.2.\nUpgrade to libwraster1-dev_0.61.1-4.1\n');
}
if (deb_check(prefix: 'wmaker', release: '2.2', reference: '0.61.1-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wmaker is vulnerable in Debian 2.2.\nUpgrade to wmaker_0.61.1-4.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
