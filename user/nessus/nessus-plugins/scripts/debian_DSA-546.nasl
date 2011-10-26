# This script was automatically generated from the dsa-546
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered several problems in gdk-pixbuf, the GdkPixBuf
library used in Gtk.  It is possible for an attacker to execute
arbitrary code on the victims machine.  Gdk-pixbuf for Gtk+1.2 is an
external package.  For Gtk+2.0 it\'s part of the main gtk package.
The Common Vulnerabilities and Exposures Project identifies the
following vulnerabilities:
    Denial of service in bmp loader.
    Heap-based overflow in pixbuf_create_from_xpm.
    Integer overflow in the ico loader.
For the stable distribution (woody) these problems have been fixed in
version 0.17.0-2woody2.
For the unstable distribution (sid) these problems have been fixed in
version 0.22.0-7.
We recommend that you upgrade your gdk-pixbuf packages.


Solution : http://www.debian.org/security/2004/dsa-546
Risk factor : High';

if (description) {
 script_id(15383);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "546");
 script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0788");
 script_xref(name: "CERT", value: "577654");
 script_xref(name: "CERT", value: "729894");
 script_xref(name: "CERT", value: "825374");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA546] DSA-546-1 gdk-pixbuf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-546-1 gdk-pixbuf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libgdk-pixbuf-dev', release: '3.0', reference: '0.17.0-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-dev is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-dev_0.17.0-2woody2\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-gnome-dev', release: '3.0', reference: '0.17.0-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-gnome-dev is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-gnome-dev_0.17.0-2woody2\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-gnome2', release: '3.0', reference: '0.17.0-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-gnome2 is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-gnome2_0.17.0-2woody2\n');
}
if (deb_check(prefix: 'libgdk-pixbuf2', release: '3.0', reference: '0.17.0-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf2 is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf2_0.17.0-2woody2\n');
}
if (deb_check(prefix: 'gdk-pixbuf', release: '3.1', reference: '0.22.0-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdk-pixbuf is vulnerable in Debian 3.1.\nUpgrade to gdk-pixbuf_0.22.0-7\n');
}
if (deb_check(prefix: 'gdk-pixbuf', release: '3.0', reference: '0.17.0-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdk-pixbuf is vulnerable in Debian woody.\nUpgrade to gdk-pixbuf_0.17.0-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
