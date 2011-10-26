# This script was automatically generated from the dsa-549
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
    Heap-based overflow in pixbuf_create_from_xpm.
    Stack-based overflow in xpm_extract_color.
    Integer overflow in the ico loader.
For the stable distribution (woody) these problems have been fixed in
version 2.0.2-5woody2.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your Gtk packages.


Solution : http://www.debian.org/security/2004/dsa-549
Risk factor : High';

if (description) {
 script_id(15386);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "549");
 script_cve_id("CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
 script_xref(name: "CERT", value: "369358");
 script_xref(name: "CERT", value: "577654");
 script_xref(name: "CERT", value: "729894");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA549] DSA-549-1 gtk+");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-549-1 gtk+");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gtk2.0-examples', release: '3.0', reference: '2.0.2-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtk2.0-examples is vulnerable in Debian 3.0.\nUpgrade to gtk2.0-examples_2.0.2-5woody2\n');
}
if (deb_check(prefix: 'libgtk-common', release: '3.0', reference: '2.0.2-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk-common is vulnerable in Debian 3.0.\nUpgrade to libgtk-common_2.0.2-5woody2\n');
}
if (deb_check(prefix: 'libgtk2.0-0', release: '3.0', reference: '2.0.2-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-0 is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-0_2.0.2-5woody2\n');
}
if (deb_check(prefix: 'libgtk2.0-common', release: '3.0', reference: '2.0.2-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-common is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-common_2.0.2-5woody2\n');
}
if (deb_check(prefix: 'libgtk2.0-dbg', release: '3.0', reference: '2.0.2-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-dbg is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-dbg_2.0.2-5woody2\n');
}
if (deb_check(prefix: 'libgtk2.0-dev', release: '3.0', reference: '2.0.2-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-dev is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-dev_2.0.2-5woody2\n');
}
if (deb_check(prefix: 'libgtk2.0-doc', release: '3.0', reference: '2.0.2-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-doc is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-doc_2.0.2-5woody2\n');
}
if (deb_check(prefix: 'gtk+2.0', release: '3.0', reference: '2.0.2-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtk+2.0 is vulnerable in Debian woody.\nUpgrade to gtk+2.0_2.0.2-5woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
