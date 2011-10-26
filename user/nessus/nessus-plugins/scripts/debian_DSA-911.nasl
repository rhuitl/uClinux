# This script was automatically generated from the dsa-911
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been found in gtk+2.0, the Gtk+ GdkPixBuf
XPM image rendering library.  The Common Vulnerabilities and Exposures
project identifies the following problems:
    Ludwig Nussel discovered an infinite loop when processing XPM
    images that allows an attacker to cause a denial of service via a
    specially crafted XPM file.
    Ludwig Nussel discovered an integer overflow in the way XPM images
    are processed that could lead to the execution of arbitrary code
    or crash the application via a specially crafted XPM file.
    "infamous41md" discovered an integer overflow in the XPM processing
    routine that can be used to execute arbitrary code via a traditional heap
    overflow.
The following matrix explains which versions fix these problems:
We recommend that you upgrade your gtk+2.0 packages.


Solution : http://www.debian.org/security/2005/dsa-911
Risk factor : High';

if (description) {
 script_id(22777);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "911");
 script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
 script_bugtraq_id(15428);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA911] DSA-911-1 gtk+2.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-911-1 gtk+2.0");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gtk2.0-examples', release: '3.0', reference: '2.0.2-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtk2.0-examples is vulnerable in Debian 3.0.\nUpgrade to gtk2.0-examples_2.0.2-5woody3\n');
}
if (deb_check(prefix: 'libgtk-common', release: '3.0', reference: '2.0.2-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk-common is vulnerable in Debian 3.0.\nUpgrade to libgtk-common_2.0.2-5woody3\n');
}
if (deb_check(prefix: 'libgtk2.0-0', release: '3.0', reference: '2.0.2-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-0 is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-0_2.0.2-5woody3\n');
}
if (deb_check(prefix: 'libgtk2.0-common', release: '3.0', reference: '2.0.2-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-common is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-common_2.0.2-5woody3\n');
}
if (deb_check(prefix: 'libgtk2.0-dbg', release: '3.0', reference: '2.0.2-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-dbg is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-dbg_2.0.2-5woody3\n');
}
if (deb_check(prefix: 'libgtk2.0-dev', release: '3.0', reference: '2.0.2-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-dev is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-dev_2.0.2-5woody3\n');
}
if (deb_check(prefix: 'libgtk2.0-doc', release: '3.0', reference: '2.0.2-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-doc is vulnerable in Debian 3.0.\nUpgrade to libgtk2.0-doc_2.0.2-5woody3\n');
}
if (deb_check(prefix: 'gtk2-engines-pixbuf', release: '3.1', reference: '2.6.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtk2-engines-pixbuf is vulnerable in Debian 3.1.\nUpgrade to gtk2-engines-pixbuf_2.6.4-3.1\n');
}
if (deb_check(prefix: 'gtk2.0-examples', release: '3.1', reference: '2.6.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtk2.0-examples is vulnerable in Debian 3.1.\nUpgrade to gtk2.0-examples_2.6.4-3.1\n');
}
if (deb_check(prefix: 'libgtk2.0-0', release: '3.1', reference: '2.6.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-0 is vulnerable in Debian 3.1.\nUpgrade to libgtk2.0-0_2.6.4-3.1\n');
}
if (deb_check(prefix: 'libgtk2.0-0-dbg', release: '3.1', reference: '2.6.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-0-dbg is vulnerable in Debian 3.1.\nUpgrade to libgtk2.0-0-dbg_2.6.4-3.1\n');
}
if (deb_check(prefix: 'libgtk2.0-bin', release: '3.1', reference: '2.6.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-bin is vulnerable in Debian 3.1.\nUpgrade to libgtk2.0-bin_2.6.4-3.1\n');
}
if (deb_check(prefix: 'libgtk2.0-common', release: '3.1', reference: '2.6.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-common is vulnerable in Debian 3.1.\nUpgrade to libgtk2.0-common_2.6.4-3.1\n');
}
if (deb_check(prefix: 'libgtk2.0-dev', release: '3.1', reference: '2.6.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-dev is vulnerable in Debian 3.1.\nUpgrade to libgtk2.0-dev_2.6.4-3.1\n');
}
if (deb_check(prefix: 'libgtk2.0-doc', release: '3.1', reference: '2.6.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtk2.0-doc is vulnerable in Debian 3.1.\nUpgrade to libgtk2.0-doc_2.6.4-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
