# This script was automatically generated from the dsa-566
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An information leak has been detected in CUPS, the Common UNIX
Printing System, which may lead to the disclosure of sensitive
information, such as user names and passwords which are written into
log files.
The used patch only eliminates the authentication information in the
device URI which is logged in the error_log file.  It does not
eliminate the URI from the environment and process table, which is why
the CUPS developers recommend that system administrators do not code
authentication information in device URIs in the first place.
For the stable distribution (woody) this problem has been fixed in
version 1.1.14-5woody7.
For the unstable distribution (sid) this problem has been fixed in
version 1.1.20final+rc1-9.
We recommend that you upgrade your CUPS package.


Solution : http://www.debian.org/security/2004/dsa-566
Risk factor : High';

if (description) {
 script_id(15664);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "566");
 script_cve_id("CVE-2004-0923");
 script_xref(name: "CERT", value: "557062");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA566] DSA-566-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-566-1 cupsys");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.0.\nUpgrade to cupsys_1.1.14-5woody7\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 3.0.\nUpgrade to cupsys-bsd_1.1.14-5woody7\n');
}
if (deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-client is vulnerable in Debian 3.0.\nUpgrade to cupsys-client_1.1.14-5woody7\n');
}
if (deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-pstoraster is vulnerable in Debian 3.0.\nUpgrade to cupsys-pstoraster_1.1.14-5woody7\n');
}
if (deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2 is vulnerable in Debian 3.0.\nUpgrade to libcupsys2_1.1.14-5woody7\n');
}
if (deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2-dev is vulnerable in Debian 3.0.\nUpgrade to libcupsys2-dev_1.1.14-5woody7\n');
}
if (deb_check(prefix: 'cupsys', release: '3.1', reference: '1.1.20final+rc1-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.1.\nUpgrade to cupsys_1.1.20final+rc1-9\n');
}
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian woody.\nUpgrade to cupsys_1.1.14-5woody7\n');
}
if (w) { security_hole(port: 0, data: desc); }
