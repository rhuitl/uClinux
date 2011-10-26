# This script was automatically generated from the dsa-140
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Developers of the PNG library have fixed a buffer overflow in the
progressive reader when the PNG datastream contains more IDAT data
than indicated by the IHDR chunk.  Such deliberately malformed
datastreams would crash applications which could potentially allow an
attacker to execute malicious code.  Programs such as Galeon,
Konqueror and various others make use of these libraries.
In addition to that, the packages below fix another
potential buffer overflow.  The PNG libraries implement a safety
margin which is also included in a newer upstream release.  Thanks to
Glenn Randers-Pehrson for informing us.
To find out which packages depend on this library, you may want to
execute the following commands:

    apt-cache showpkg libpng2
    apt-cache showpkg libpng3


This problem has been fixed in version 1.0.12-3.woody.2 of libpng and
version 1.2.1-1.1.woody.2 of libpng3 for the current stable
distribution (woody) and in version 1.0.12-4 of libpng and version
1.2.1-2 of libpng3 for the unstable distribution (sid).
The potato release of Debian does not seem to be vulnerable.
We recommend that you upgrade your libpng packages immediately and
restart programs and daemons that link to these libraries and read
external data, such as web browsers.


Solution : http://www.debian.org/security/2002/dsa-140
Risk factor : High';

if (description) {
 script_id(14977);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "140");
 script_cve_id("CVE-2002-0660", "CVE-2002-0728");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA140] DSA-140-2 libpng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-140-2 libpng");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpng-dev', release: '3.0', reference: '1.2.1-1.1.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng-dev is vulnerable in Debian 3.0.\nUpgrade to libpng-dev_1.2.1-1.1.woody.2\n');
}
if (deb_check(prefix: 'libpng2', release: '3.0', reference: '1.0.12-3.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2 is vulnerable in Debian 3.0.\nUpgrade to libpng2_1.0.12-3.woody.2\n');
}
if (deb_check(prefix: 'libpng2-dev', release: '3.0', reference: '1.0.12-3.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2-dev is vulnerable in Debian 3.0.\nUpgrade to libpng2-dev_1.0.12-3.woody.2\n');
}
if (deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng3 is vulnerable in Debian 3.0.\nUpgrade to libpng3_1.2.1-1.1.woody.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
