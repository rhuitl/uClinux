# This script was automatically generated from the dsa-176
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Zen-parse discovered a buffer overflow in gv, a PostScript and PDF
viewer for X11.  This problem is triggered by scanning the PostScript
file and can be exploited by an attacker sending a malformed
PostScript or PDF file.  The attacker is able to cause arbitrary code
to be run with the privileges of the victim.
This problem has been fixed in version 3.5.8-26.1 for the current
stable distribution (woody), in version 3.5.8-17.1 for the old stable
distribution (potato) and version 3.5.8-27 for the unstable
distribution (sid).
We recommend that you upgrade your gv package.


Solution : http://www.debian.org/security/2002/dsa-176
Risk factor : High';

if (description) {
 script_id(15013);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "176");
 script_cve_id("CVE-2002-0838");
 script_bugtraq_id(5808);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA176] DSA-176-1 gv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-176-1 gv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gv', release: '2.2', reference: '3.5.8-17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gv is vulnerable in Debian 2.2.\nUpgrade to gv_3.5.8-17.1\n');
}
if (deb_check(prefix: 'gv', release: '3.0', reference: '3.5.8-26.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gv is vulnerable in Debian 3.0.\nUpgrade to gv_3.5.8-26.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
