# This script was automatically generated from the dsa-085
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Takeshi Uno found a very stupid format string vulnerability in all
versions of nvi (in both, the plain and the multilingualized version).
When a filename is saved, it ought to get displayed on the screen.
The routine handling this didn\'t escape format strings.

This problem has been fixed in version 1.79-16a.1 for nvi and
1.79+19991117-2.3 for nvi-m17n for the stable Debian GNU/Linux 2.2.

Even if we don\'t believe that this could lead into somebody gaining
access of another users account if they haven\'t lost their brain, we
recommend that you upgrade your nvi packages.



Solution : http://www.debian.org/security/2001/dsa-085
Risk factor : High';

if (description) {
 script_id(14922);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "085");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA085] DSA-085-1 nvi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-085-1 nvi");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nvi', release: '2.2', reference: '1.79-16a.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nvi is vulnerable in Debian 2.2.\nUpgrade to nvi_1.79-16a.1\n');
}
if (deb_check(prefix: 'nvi-m17n', release: '2.2', reference: '1.79+19991117-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nvi-m17n is vulnerable in Debian 2.2.\nUpgrade to nvi-m17n_1.79+19991117-2.3\n');
}
if (deb_check(prefix: 'nvi-m17n-canna', release: '2.2', reference: '1.79+19991117-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nvi-m17n-canna is vulnerable in Debian 2.2.\nUpgrade to nvi-m17n-canna_1.79+19991117-2.3\n');
}
if (deb_check(prefix: 'nvi-m17n-common', release: '2.2', reference: '1.79+19991117-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nvi-m17n-common is vulnerable in Debian 2.2.\nUpgrade to nvi-m17n-common_1.79+19991117-2.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
