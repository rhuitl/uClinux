# This script was automatically generated from the dsa-591
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" discovered several integer overflows in the PNG image
decoding routines of the GD graphics library.  This could lead to the
execution of arbitrary code on the victim\'s machine.
For the stable distribution (woody) these problems have been fixed in
version 1.8.4-17.woody3 of libgd1 and in version 2.0.1-10woody1 of
libgd2.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your libgd2 packages.


Solution : http://www.debian.org/security/2004/dsa-591
Risk factor : High';

if (description) {
 script_id(15689);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "591");
 script_cve_id("CVE-2004-0990");
 script_bugtraq_id(11523);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA591] DSA-591-1 libgd2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-591-1 libgd2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libgd-tools', release: '3.0', reference: '2.0.1-10woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd-tools is vulnerable in Debian 3.0.\nUpgrade to libgd-tools_2.0.1-10woody1\n');
}
if (deb_check(prefix: 'libgd2', release: '3.0', reference: '2.0.1-10woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2 is vulnerable in Debian 3.0.\nUpgrade to libgd2_2.0.1-10woody1\n');
}
if (deb_check(prefix: 'libgd2-dev', release: '3.0', reference: '2.0.1-10woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2-dev is vulnerable in Debian 3.0.\nUpgrade to libgd2-dev_2.0.1-10woody1\n');
}
if (deb_check(prefix: 'libgd2-noxpm', release: '3.0', reference: '2.0.1-10woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2-noxpm is vulnerable in Debian 3.0.\nUpgrade to libgd2-noxpm_2.0.1-10woody1\n');
}
if (deb_check(prefix: 'libgd2', release: '3.0', reference: '1.8.4-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2 is vulnerable in Debian woody.\nUpgrade to libgd2_1.8.4-17\n');
}
if (w) { security_hole(port: 0, data: desc); }
