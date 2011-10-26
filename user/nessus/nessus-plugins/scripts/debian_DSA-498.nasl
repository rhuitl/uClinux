# This script was automatically generated from the dsa-498
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Grubb discovered a problem in the Portable Network Graphics
library libpng which is utilised in several applications.  When
processing a broken PNG image, the error handling routine will access
memory that is out of bounds when creating an error message.
Depending on machine architecture, bounds checking and other
protective measures, this problem could cause the program to crash if
a defective or intentionally prepared PNG image file is handled by
libpng.
This could be used as a denial of service attack against various
programs that link against this library.  The following commands will
show you which packages utilise this library and whose programs should
probably restarted after an upgrade:

   apt-cache showpkg libpng2
   apt-cache showpkg libpng3


The following security matrix explains which package versions will
contain a correction.
We recommend that you upgrade your libpng and related packages.


Solution : http://www.debian.org/security/2004/dsa-498
Risk factor : High';

if (description) {
 script_id(15335);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "498");
 script_cve_id("CVE-2004-0421");
 script_bugtraq_id(10244);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA498] DSA-498-1 libpng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-498-1 libpng");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpng-dev', release: '3.0', reference: '1.2.1-1.1.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng-dev is vulnerable in Debian 3.0.\nUpgrade to libpng-dev_1.2.1-1.1.woody.5\n');
}
if (deb_check(prefix: 'libpng2', release: '3.0', reference: '1.0.12-3.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2 is vulnerable in Debian 3.0.\nUpgrade to libpng2_1.0.12-3.woody.5\n');
}
if (deb_check(prefix: 'libpng2-dev', release: '3.0', reference: '1.0.12-3.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2-dev is vulnerable in Debian 3.0.\nUpgrade to libpng2-dev_1.0.12-3.woody.5\n');
}
if (deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng3 is vulnerable in Debian 3.0.\nUpgrade to libpng3_1.2.1-1.1.woody.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
