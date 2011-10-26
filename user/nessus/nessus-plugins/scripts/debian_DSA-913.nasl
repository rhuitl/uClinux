# This script was automatically generated from the dsa-913
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been found in gdk-pixbuf, the Gtk+
GdkPixBuf XPM image rendering library.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Ludwig Nussel discovered an infinite loop when processing XPM
    images that allows an attacker to cause a denial of service via a
    specially crafted XPM file.
    Ludwig Nussel discovered an integer overflow in the way XPM images
    are processed that could lead to the execution of arbitrary code
    or crash the application via a specially crafted XPM file.
    "infamous41md" discovered an integer in the XPM processing routine
    that can be used to execute arbitrary code via a traditional heap
    overflow.
The following matrix explains which versions fix these problems:
We recommend that you upgrade your gdk-pixbuf packages.


Solution : http://www.debian.org/security/2005/dsa-913
Risk factor : High';

if (description) {
 script_id(22779);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "913");
 script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
 script_bugtraq_id(15428);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA913] DSA-913-1 gdk-pixbuf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-913-1 gdk-pixbuf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libgdk-pixbuf-dev', release: '3.0', reference: '0.17.0-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-dev is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-dev_0.17.0-2woody3\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-gnome-dev', release: '3.0', reference: '0.17.0-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-gnome-dev is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-gnome-dev_0.17.0-2woody3\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-gnome2', release: '3.0', reference: '0.17.0-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-gnome2 is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf-gnome2_0.17.0-2woody3\n');
}
if (deb_check(prefix: 'libgdk-pixbuf2', release: '3.0', reference: '0.17.0-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf2 is vulnerable in Debian 3.0.\nUpgrade to libgdk-pixbuf2_0.17.0-2woody3\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-dev', release: '3.1', reference: '0.22.0-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-dev is vulnerable in Debian 3.1.\nUpgrade to libgdk-pixbuf-dev_0.22.0-8.1\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-gnome-dev', release: '3.1', reference: '0.22.0-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-gnome-dev is vulnerable in Debian 3.1.\nUpgrade to libgdk-pixbuf-gnome-dev_0.22.0-8.1\n');
}
if (deb_check(prefix: 'libgdk-pixbuf-gnome2', release: '3.1', reference: '0.22.0-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf-gnome2 is vulnerable in Debian 3.1.\nUpgrade to libgdk-pixbuf-gnome2_0.22.0-8.1\n');
}
if (deb_check(prefix: 'libgdk-pixbuf2', release: '3.1', reference: '0.22.0-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdk-pixbuf2 is vulnerable in Debian 3.1.\nUpgrade to libgdk-pixbuf2_0.22.0-8.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
