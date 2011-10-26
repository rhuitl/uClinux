# This script was automatically generated from the dsa-179
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Zen-parse discovered a buffer overflow in gv, a PostScript and PDF
viewer for X11.  The same code is present in gnome-gv.  This problem
is triggered by scanning the PostScript file and can be exploited by
an attacker sending a malformed PostScript or PDF file.  The attacker
is able to cause arbitrary code to be run with the privileges of the
victim.
This problem has been fixed in version 1.1.96-3.1 for the current
stable distribution (woody), in version 0.82-2.1 for the old stable
distribution (potato) and version 1.99.7-9 for the unstable
distribution (sid).
We recommend that you upgrade your gnome-gv package.


Solution : http://www.debian.org/security/2002/dsa-179
Risk factor : High';

if (description) {
 script_id(15016);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "179");
 script_cve_id("CVE-2002-0838");
 script_bugtraq_id(5808);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA179] DSA-179-1 gnome-gv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-179-1 gnome-gv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnome-gv', release: '2.2', reference: '0.82-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnome-gv is vulnerable in Debian 2.2.\nUpgrade to gnome-gv_0.82-2.1\n');
}
if (deb_check(prefix: 'gnome-gv', release: '3.0', reference: '1.1.96-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnome-gv is vulnerable in Debian 3.0.\nUpgrade to gnome-gv_1.1.96-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
