# This script was automatically generated from the dsa-822
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Eric Romang discovered that gtkdiskfree, a GNOME program that shows
free and used space on filesystems, creates a temporary file in an
insecure fashion.
The old stable distribution (woody) does not contain the gtkdiskfree
package.
For the stable distribution (sarge) this problem has been fixed in
version 1.9.3-4sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your gtkdiskfree package.


Solution : http://www.debian.org/security/2005/dsa-822
Risk factor : High';

if (description) {
 script_id(19791);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "822");
 script_cve_id("CVE-2005-2918");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA822] DSA-822-1 gtkdiskfree");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-822-1 gtkdiskfree");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gtkdiskfree', release: '3.1', reference: '1.9.3-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtkdiskfree is vulnerable in Debian 3.1.\nUpgrade to gtkdiskfree_1.9.3-4sarge1\n');
}
if (deb_check(prefix: 'gtkdiskfree', release: '3.1', reference: '1.9.3-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtkdiskfree is vulnerable in Debian sarge.\nUpgrade to gtkdiskfree_1.9.3-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
