# This script was automatically generated from the dsa-037
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'It has been reported that the AsciiSrc and MultiSrc widget
in the Athena widget library handle temporary files insecurely.  Joey Hess has
ported the bugfix from XFree86 to these Xaw replacements libraries. The fixes
are available in nextaw 0.5.1-34potato1, xaw3d 1.3-6.9potato1, and xaw95
1.1-4.6potato1.


Solution : http://www.debian.org/security/2001/dsa-037
Risk factor : High';

if (description) {
 script_id(14874);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "037");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA037] DSA-037-1 Athena Widget replacement libraries");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-037-1 Athena Widget replacement libraries");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nextaw', release: '2.2', reference: '0.5.1-34potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nextaw is vulnerable in Debian 2.2.\nUpgrade to nextaw_0.5.1-34potato1\n');
}
if (deb_check(prefix: 'nextawg', release: '2.2', reference: '0.5.1-34potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nextawg is vulnerable in Debian 2.2.\nUpgrade to nextawg_0.5.1-34potato1\n');
}
if (deb_check(prefix: 'xaw3d', release: '2.2', reference: '1.3-6.9potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaw3d is vulnerable in Debian 2.2.\nUpgrade to xaw3d_1.3-6.9potato1\n');
}
if (deb_check(prefix: 'xaw3dg', release: '2.2', reference: '1.3-6.9potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaw3dg is vulnerable in Debian 2.2.\nUpgrade to xaw3dg_1.3-6.9potato1\n');
}
if (deb_check(prefix: 'xaw3dg-dev', release: '2.2', reference: '1.3-6.9potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaw3dg-dev is vulnerable in Debian 2.2.\nUpgrade to xaw3dg-dev_1.3-6.9potato1\n');
}
if (deb_check(prefix: 'xaw95g', release: '2.2', reference: '1.1-4.6potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaw95g is vulnerable in Debian 2.2.\nUpgrade to xaw95g_1.1-4.6potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
