# This script was automatically generated from the dsa-807
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in mod_ssl, which provides strong
cryptography (HTTPS support) for Apache that allows remote attackers
to bypass access restrictions.
For the old stable distribution (woody) this problem has been fixed in
version 2.8.9-2.5.
For the stable distribution (sarge) this problem has been fixed in
version 2.8.22-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.8.24-1.
We recommend that you upgrade your libapache-mod-ssl package.


Solution : http://www.debian.org/security/2005/dsa-807
Risk factor : High';

if (description) {
 script_id(19682);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "807");
 script_cve_id("CVE-2005-2700");
 script_bugtraq_id(14721);
 script_xref(name: "CERT", value: "744929");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA807] DSA-807-1 libapache-mod-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-807-1 libapache-mod-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-mod-ssl', release: '', reference: '2.8.24-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian .\nUpgrade to libapache-mod-ssl_2.8.24-1\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-ssl_2.8.9-2.5\n');
}
if (deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.0', reference: '2.8.9-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl-doc is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-ssl-doc_2.8.9-2.5\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.1', reference: '2.8.22-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-ssl_2.8.22-1sarge1\n');
}
if (deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.1', reference: '2.8.22-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl-doc is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-ssl-doc_2.8.22-1sarge1\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.1', reference: '2.8.22-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian sarge.\nUpgrade to libapache-mod-ssl_2.8.22-1sarge1\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian woody.\nUpgrade to libapache-mod-ssl_2.8.9-2.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
