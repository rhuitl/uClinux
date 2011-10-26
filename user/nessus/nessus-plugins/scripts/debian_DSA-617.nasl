# This script was automatically generated from the dsa-617
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" discovered a problem in libtiff, the Tag Image File
Format library for processing TIFF graphics files.  Upon reading a
TIFF file it is possible to allocate a zero sized buffer and write to
it which would lead to the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 3.5.5-6.woody3.
For the unstable distribution (sid) this problem has been fixed in
version 3.6.1-4.
We recommend that you upgrade your libtiff packages immediately.


Solution : http://www.debian.org/security/2004/dsa-617
Risk factor : High';

if (description) {
 script_id(16048);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "617");
 script_cve_id("CVE-2004-1308");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA617] DSA-617-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-617-1 tiff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-6.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.0.\nUpgrade to libtiff-tools_3.5.5-6.woody3\n');
}
if (deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-6.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g is vulnerable in Debian 3.0.\nUpgrade to libtiff3g_3.5.5-6.woody3\n');
}
if (deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-6.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g-dev is vulnerable in Debian 3.0.\nUpgrade to libtiff3g-dev_3.5.5-6.woody3\n');
}
if (deb_check(prefix: 'tiff', release: '3.1', reference: '3.6.1-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian 3.1.\nUpgrade to tiff_3.6.1-4\n');
}
if (deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-6.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian woody.\nUpgrade to tiff_3.5.5-6.woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
