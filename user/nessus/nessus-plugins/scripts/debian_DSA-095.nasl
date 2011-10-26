# This script was automatically generated from the dsa-095
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The package \'gpm\' contains the gpm-root program, which can be used to
create mouse-activated menus on the console.
Among other problems, the gpm-root program contains a format string
vulnerability, which allows an attacker to gain root privileges.

This has been fixed in version 1.17.8-18.1, and we recommend that you upgrade
your 1.17.8-18 package immediately.


Solution : http://www.debian.org/security/2001/dsa-095
Risk factor : High';

if (description) {
 script_id(14932);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "095");
 script_cve_id("CVE-2001-1203");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA095] DSA-095-1 gpm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-095-1 gpm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gpm', release: '2.2', reference: '1.17.8-18.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpm is vulnerable in Debian 2.2.\nUpgrade to gpm_1.17.8-18.1\n');
}
if (deb_check(prefix: 'libgpm1', release: '2.2', reference: '1.17.8-18.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgpm1 is vulnerable in Debian 2.2.\nUpgrade to libgpm1_1.17.8-18.1\n');
}
if (deb_check(prefix: 'libgpm1-altdev', release: '2.2', reference: '1.17.8-18.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgpm1-altdev is vulnerable in Debian 2.2.\nUpgrade to libgpm1-altdev_1.17.8-18.1\n');
}
if (deb_check(prefix: 'libgpmg1', release: '2.2', reference: '1.17.8-18.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgpmg1 is vulnerable in Debian 2.2.\nUpgrade to libgpmg1_1.17.8-18.1\n');
}
if (deb_check(prefix: 'libgpmg1-dev', release: '2.2', reference: '1.17.8-18.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgpmg1-dev is vulnerable in Debian 2.2.\nUpgrade to libgpmg1-dev_1.17.8-18.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
