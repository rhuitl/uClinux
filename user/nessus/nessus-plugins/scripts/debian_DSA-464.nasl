# This script was automatically generated from the dsa-464
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Thomas Kristensen discovered a vulnerability in gdk-pixbuf (binary
package libgdk-pixbuf2), the GdkPixBuf image library for Gtk, that can
cause the surrounding application to crash.  To exploit this problem,
a remote attacker could send a carefully-crafted BMP file via mail,
which would cause e.g. Evolution to crash but is probably not limited
to Evolution.
For the stable distribution (woody) this problem has been fixed in
version 0.17.0-2woody1.
For the unstable distribution (sid) this problem has been fixed in
version 0.22.0-3.
We recommend that you upgrade your libgdk-pixbuf2 package.


Solution : http://www.debian.org/security/2004/dsa-464
Risk factor : High';

if (description) {
 script_id(15301);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "464");
 script_cve_id("CVE-2004-0111");
 script_bugtraq_id(9842);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA464] DSA-464-1 gdk-pixbuf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-464-1 gdk-pixbuf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libgdk-pixbuf-dev', release: '3.0', reference: '0.17.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-dev is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-dev_0.17.0-2woody1\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-gnome-dev', release: '3.0', reference: '0.17.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-gnome-dev is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-gnome-dev_0.17.0-2woody1\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-gnome2', release: '3.0', reference: '0.17.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-gnome2 is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-gnome2_0.17.0-2woody1\n');
}
if (deb_check(prefix: 'libgdk-pixbuf2', release: '3.0', reference: '0.17.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf2 is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf2_0.17.0-2woody1\n');
}
if (deb_check(prefix: 'gdk-pixbuf', release: '3.1', reference: '0.22.0-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdk-pixbuf is vulnerable in Debian 3.1.\nUpgrade to gdk-pixbuf_0.22.0-3\n');
}
if (deb_check(prefix: 'gdk-pixbuf', release: '3.0', reference: '0.17.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdk-pixbuf is vulnerable in Debian woody.\nUpgrade to gdk-pixbuf_0.17.0-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
