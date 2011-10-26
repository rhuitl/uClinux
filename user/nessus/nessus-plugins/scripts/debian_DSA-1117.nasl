# This script was automatically generated from the dsa-1117
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It was discovered that the GD graphics library performs insufficient checks
of the validity of GIF images, which might lead to denial of service by
tricking the application into an infinite loop.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.33-1.1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.33-5.
We recommend that you upgrade your libgd2 packages.


Solution : http://www.debian.org/security/2006/dsa-1117
Risk factor : High';

if (description) {
 script_id(22659);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1117");
 script_cve_id("CVE-2006-2906");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1117] DSA-1117-1 libgd2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1117-1 libgd2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libgd2', release: '', reference: '2.0.33-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2 is vulnerable in Debian .\nUpgrade to libgd2_2.0.33-5\n');
}
if (deb_check(prefix: 'libgd-tools', release: '3.1', reference: '2.0.33-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd-tools is vulnerable in Debian 3.1.\nUpgrade to libgd-tools_2.0.33-1.1sarge1\n');
}
if (deb_check(prefix: 'libgd2', release: '3.1', reference: '2.0.33-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2 is vulnerable in Debian 3.1.\nUpgrade to libgd2_2.0.33-1.1sarge1\n');
}
if (deb_check(prefix: 'libgd2-dev', release: '3.1', reference: '2.0.33-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2-dev is vulnerable in Debian 3.1.\nUpgrade to libgd2-dev_2.0.33-1.1sarge1\n');
}
if (deb_check(prefix: 'libgd2-noxpm', release: '3.1', reference: '2.0.33-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2-noxpm is vulnerable in Debian 3.1.\nUpgrade to libgd2-noxpm_2.0.33-1.1sarge1\n');
}
if (deb_check(prefix: 'libgd2-noxpm-dev', release: '3.1', reference: '2.0.33-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2-noxpm-dev is vulnerable in Debian 3.1.\nUpgrade to libgd2-noxpm-dev_2.0.33-1.1sarge1\n');
}
if (deb_check(prefix: 'libgd2-xpm', release: '3.1', reference: '2.0.33-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2-xpm is vulnerable in Debian 3.1.\nUpgrade to libgd2-xpm_2.0.33-1.1sarge1\n');
}
if (deb_check(prefix: 'libgd2-xpm-dev', release: '3.1', reference: '2.0.33-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2-xpm-dev is vulnerable in Debian 3.1.\nUpgrade to libgd2-xpm-dev_2.0.33-1.1sarge1\n');
}
if (deb_check(prefix: 'libgd2', release: '3.1', reference: '2.0.33-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd2 is vulnerable in Debian sarge.\nUpgrade to libgd2_2.0.33-1.1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
