# This script was automatically generated from the dsa-120
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ed Moyle recently
found a buffer overflow in Apache-SSL and mod_ssl.
With session caching enabled, mod_ssl will serialize SSL session
variables to store them for later use.  These variables were stored in
a buffer of a fixed size without proper boundary checks.
To exploit the overflow, the server must be configured to require client
certificates, and an attacker must obtain a carefully crafted client
certificate that has been signed by a Certificate Authority which is
trusted by the server. If these conditions are met, it would be possible
for an attacker to execute arbitrary code on the server.
This problem has been fixed in version 1.3.9.13-4 of Apache-SSL and
version 2.4.10-1.3.9-1potato1 of libapache-mod-ssl for the stable
Debian distribution as well as in version 1.3.23.1+1.47-1 of
Apache-SSL and version 2.8.7-1 of libapache-mod-ssl for the testing
and unstable distribution of Debian.
We recommend that you upgrade your Apache-SSL and mod_ssl packages.


Solution : http://www.debian.org/security/2002/dsa-120
Risk factor : High';

if (description) {
 script_id(14957);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "120");
 script_cve_id("CVE-2002-0082");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA120] DSA-120-1 mod_ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-120-1 mod_ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache-ssl', release: '2.2', reference: '1.3.9.13-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-ssl is vulnerable in Debian 2.2.\nUpgrade to apache-ssl_1.3.9.13-4\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '2.2', reference: '2.4.10-1.3.9-1potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 2.2.\nUpgrade to libapache-mod-ssl_2.4.10-1.3.9-1potato1\n');
}
if (deb_check(prefix: 'libapache-mod-ssl-doc', release: '2.2', reference: '2.4.10-1.3.9-1potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl-doc is vulnerable in Debian 2.2.\nUpgrade to libapache-mod-ssl-doc_2.4.10-1.3.9-1potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
