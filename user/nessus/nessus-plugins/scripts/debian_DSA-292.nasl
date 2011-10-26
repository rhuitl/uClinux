# This script was automatically generated from the dsa-292
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Colin Phipps discovered several problems in mime-support, that contains
support programs for the MIME control files \'mime.types\' and \'mailcap\'.
When a temporary file is to be used it is created insecurely, allowing
an attacker to overwrite arbitrary under the user id of the person
executing run-mailcap.
When run-mailcap is executed on a file with a potentially
problematic filename, a temporary file is created (not insecurely
anymore), removed and a symbolic link to this filename is created.  An
attacker could recreate the file before the symbolic link is created,
forcing the display program to display different content.
For the stable distribution (woody) these problems have been fixed in
version 3.18-1.3.
For the old stable distribution (potato) these problems have been
fixed in version 3.9-1.3.
For the unstable distribution (sid) these problems have been
fixed in version 3.23-1.
We recommend that you upgrade your mime-support packages.


Solution : http://www.debian.org/security/2003/dsa-292
Risk factor : High';

if (description) {
 script_id(15129);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "292");
 script_cve_id("CVE-2003-0214");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA292] DSA-292-3 mime-support");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-292-3 mime-support");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mime-support', release: '2.2', reference: '3.9-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mime-support is vulnerable in Debian 2.2.\nUpgrade to mime-support_3.9-1.3\n');
}
if (deb_check(prefix: 'mime-support', release: '3.0', reference: '3.18-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mime-support is vulnerable in Debian 3.0.\nUpgrade to mime-support_3.18-1.3\n');
}
if (deb_check(prefix: 'mime-support', release: '3.1', reference: '3.23-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mime-support is vulnerable in Debian 3.1.\nUpgrade to mime-support_3.23-1\n');
}
if (deb_check(prefix: 'mime-support', release: '2.2', reference: '3.9-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mime-support is vulnerable in Debian potato.\nUpgrade to mime-support_3.9-1.3\n');
}
if (deb_check(prefix: 'mime-support', release: '3.0', reference: '3.18-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mime-support is vulnerable in Debian woody.\nUpgrade to mime-support_3.18-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
