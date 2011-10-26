# This script was automatically generated from the dsa-107
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Basically, this is the same Security Advisory as <a
href="$(HOME)/security/2001/dsa-072">DSA 072-1</a>, but for
jgroff instead of groff.  The package jgroff contains a version
derived from groff that has Japanese character sets enabled.  This
package is available only in the stable release of Debian, patches for
Japanese support have been merged into the main groff package.

The old advisory said:

Zenith Parse found a security problem in groff (the GNU version of
troff).  The pic command was vulnerable to a printf format attack
which made it possible to circumvent the `-S\' option and execute
arbitrary code.



Solution : http://www.debian.org/security/2002/dsa-107
Risk factor : High';

if (description) {
 script_id(14944);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "107");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA107] DSA-107-1 jgroff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-107-1 jgroff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'jgroff', release: '2.2', reference: '1.15+ja-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package jgroff is vulnerable in Debian 2.2.\nUpgrade to jgroff_1.15+ja-3.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
