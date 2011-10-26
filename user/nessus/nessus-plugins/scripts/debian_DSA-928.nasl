# This script was automatically generated from the dsa-928
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that two scripts in the dhis-tools-dns package, DNS
configuration utilities for a dynamic host information System, which
are usually executed by root, create temporary files in an insecure
fashion.
The old stable distribution (woody) does not contain a dhis-tools-dns
package.
For the stable distribution (sarge) these problems have been fixed in
version 5.0-3sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 5.0-5.
We recommend that you upgrade your dhis-tools-dns package.


Solution : http://www.debian.org/security/2005/dsa-928
Risk factor : High';

if (description) {
 script_id(22794);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "928");
 script_cve_id("CVE-2005-3341");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA928] DSA-928-1 dhis-tools-dns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-928-1 dhis-tools-dns");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dhis-tools-dns', release: '', reference: '5.0-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhis-tools-dns is vulnerable in Debian .\nUpgrade to dhis-tools-dns_5.0-5\n');
}
if (deb_check(prefix: 'dhis-tools-dns', release: '3.1', reference: '5.0-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhis-tools-dns is vulnerable in Debian 3.1.\nUpgrade to dhis-tools-dns_5.0-3sarge1\n');
}
if (deb_check(prefix: 'dhis-tools-genkeys', release: '3.1', reference: '5.0-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhis-tools-genkeys is vulnerable in Debian 3.1.\nUpgrade to dhis-tools-genkeys_5.0-3sarge1\n');
}
if (deb_check(prefix: 'dhis-tools-dns', release: '3.1', reference: '5.0-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhis-tools-dns is vulnerable in Debian sarge.\nUpgrade to dhis-tools-dns_5.0-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
