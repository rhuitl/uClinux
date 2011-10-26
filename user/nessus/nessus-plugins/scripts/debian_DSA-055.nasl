# This script was automatically generated from the dsa-055
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A new Zope hotfix has been released which fixes a problem in ZClasses.
The README for the 2001-05-01 hotfix describes the problem as `any user
can visit a ZClass declaration and change the ZClass permission mappings
for methods and other objects defined within the ZClass, possibly
allowing for unauthorized access within the Zope instance.\'

This hotfix has been added in version 2.1.6-10, and we highly recommend
that you upgrade your zope package immediately.



Solution : http://www.debian.org/security/2001/dsa-055
Risk factor : High';

if (description) {
 script_id(14892);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "055");
 script_cve_id("CVE-2001-0567");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA055] DSA-055-1 zope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-055-1 zope");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zope', release: '2.2', reference: '2.1.6-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope is vulnerable in Debian 2.2.\nUpgrade to zope_2.1.6-10\n');
}
if (w) { security_hole(port: 0, data: desc); }
