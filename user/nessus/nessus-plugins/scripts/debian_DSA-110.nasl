# This script was automatically generated from the dsa-110
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The authors of CUPS, the Common UNIX Printing System, have found a
potential buffer overflow bug in the code of the CUPS daemon where it
reads the names of attributes.  This affects all versions of CUPS.
This problem has been fixed in version 1.0.4-10 for the stable Debian
distribution and version 1.1.13-2 for the current testing/unstable
distribution.
We recommend that you upgrade your CUPS packages immediately if you
have them installed.


Solution : http://www.debian.org/security/2002/dsa-110
Risk factor : High';

if (description) {
 script_id(14947);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "110");
 script_cve_id("CVE-2002-0063");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA110] DSA-110-1 cups");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-110-1 cups");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cupsys', release: '2.2', reference: '1.0.4-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 2.2.\nUpgrade to cupsys_1.0.4-10\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '2.2', reference: '1.0.4-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 2.2.\nUpgrade to cupsys-bsd_1.0.4-10\n');
}
if (deb_check(prefix: 'libcupsys1', release: '2.2', reference: '1.0.4-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys1 is vulnerable in Debian 2.2.\nUpgrade to libcupsys1_1.0.4-10\n');
}
if (deb_check(prefix: 'libcupsys1-dev', release: '2.2', reference: '1.0.4-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys1-dev is vulnerable in Debian 2.2.\nUpgrade to libcupsys1-dev_1.0.4-10\n');
}
if (w) { security_hole(port: 0, data: desc); }
