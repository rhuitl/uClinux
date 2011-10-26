# This script was automatically generated from the dsa-640
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered a buffer overflow in xatitv, one of the
programs in the gatos package, that is used to display video with
certain ATI video cards.  xatitv is installed setuid root in order to
gain direct access to the video hardware.
For the stable distribution (woody) this problem has been fixed in
version 0.0.5-6woody3.
For the unstable distribution (sid) this problem has been fixed in
version 0.0.5-15.
We recommend that you upgrade your gatos package.


Solution : http://www.debian.org/security/2005/dsa-640
Risk factor : High';

if (description) {
 script_id(16176);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "640");
 script_cve_id("CVE-2005-0016");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA640] DSA-640-1 gatos");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-640-1 gatos");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gatos', release: '3.0', reference: '0.0.5-6woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gatos is vulnerable in Debian 3.0.\nUpgrade to gatos_0.0.5-6woody3\n');
}
if (deb_check(prefix: 'libgatos-dev', release: '3.0', reference: '0.0.5-6woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgatos-dev is vulnerable in Debian 3.0.\nUpgrade to libgatos-dev_0.0.5-6woody3\n');
}
if (deb_check(prefix: 'libgatos0', release: '3.0', reference: '0.0.5-6woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgatos0 is vulnerable in Debian 3.0.\nUpgrade to libgatos0_0.0.5-6woody3\n');
}
if (deb_check(prefix: 'gatos', release: '3.1', reference: '0.0.5-15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gatos is vulnerable in Debian 3.1.\nUpgrade to gatos_0.0.5-15\n');
}
if (deb_check(prefix: 'gatos', release: '3.0', reference: '0.0.5-6woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gatos is vulnerable in Debian woody.\nUpgrade to gatos_0.0.5-6woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
