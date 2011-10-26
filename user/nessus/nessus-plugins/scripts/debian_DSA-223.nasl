# This script was automatically generated from the dsa-223
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A security issue has been discovered by Daniel de Rauglaudre, upstream
author of geneweb, a genealogical software with web interface.  It
runs as a daemon on port 2317 by default.  Paths are not properly
sanitized, so a carefully crafted URL lead geneweb to read and display
arbitrary files of the system it runs on.
For the current stable distribution (woody) this problem has been
fixed in version 4.06-2.
The old stable distribution (potato) is not affected.
For the unstable distribution (sid) this problem has been
fixed in version 4.09-1.
We recommend that you upgrade your geneweb package.


Solution : http://www.debian.org/security/2003/dsa-223
Risk factor : High';

if (description) {
 script_id(15060);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "223");
 script_cve_id("CVE-2002-1390");
 script_bugtraq_id(6549);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA223] DSA-223-1 geneweb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-223-1 geneweb");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'geneweb', release: '3.0', reference: '4.06-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package geneweb is vulnerable in Debian 3.0.\nUpgrade to geneweb_4.06-2\n');
}
if (deb_check(prefix: 'gwtp', release: '3.0', reference: '4.06-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gwtp is vulnerable in Debian 3.0.\nUpgrade to gwtp_4.06-2\n');
}
if (deb_check(prefix: 'geneweb', release: '3.1', reference: '4.09-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package geneweb is vulnerable in Debian 3.1.\nUpgrade to geneweb_4.09-1\n');
}
if (deb_check(prefix: 'geneweb', release: '3.0', reference: '4.06-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package geneweb is vulnerable in Debian woody.\nUpgrade to geneweb_4.06-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
