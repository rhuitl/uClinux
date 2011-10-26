# This script was automatically generated from the dsa-601
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
More potential integer overflows have been found in the GD graphics
library which weren\'t covered by our security advisory 
DSA 589.  They
could be exploited by a specially crafted graphic and could lead to
the execution of arbitrary code on the victim\'s machine.
For the stable distribution (woody) these problems have been fixed in
version 1.8.4-17.woody4.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your libgd1 packages.


Solution : http://www.debian.org/security/2004/dsa-601
Risk factor : High';

if (description) {
 script_id(15844);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "601");
 script_cve_id("CVE-2004-0941", "CVE-2004-0990");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA601] DSA-601-1 libgd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-601-1 libgd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libgd-dev', release: '3.0', reference: '1.8.4-17.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd-dev is vulnerable in Debian 3.0.\nUpgrade to libgd-dev_1.8.4-17.woody4\n');
}
if (deb_check(prefix: 'libgd-noxpm-dev', release: '3.0', reference: '1.8.4-17.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd-noxpm-dev is vulnerable in Debian 3.0.\nUpgrade to libgd-noxpm-dev_1.8.4-17.woody4\n');
}
if (deb_check(prefix: 'libgd1', release: '3.0', reference: '1.8.4-17.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd1 is vulnerable in Debian 3.0.\nUpgrade to libgd1_1.8.4-17.woody4\n');
}
if (deb_check(prefix: 'libgd1-noxpm', release: '3.0', reference: '1.8.4-17.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd1-noxpm is vulnerable in Debian 3.0.\nUpgrade to libgd1-noxpm_1.8.4-17.woody4\n');
}
if (deb_check(prefix: 'libgd1', release: '3.0', reference: '1.8.4-17.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgd1 is vulnerable in Debian woody.\nUpgrade to libgd1_1.8.4-17.woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
