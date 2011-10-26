# This script was automatically generated from the dsa-865
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña discovered that several scripts of the
hylafax suite, a flexible client/server fax software, create temporary
files and directories in an insecure fashion, leaving them vulnerable
to symlink exploits.
For the old stable distribution (woody) this problem has been fixed in
version 4.1.1-3.2.
For the stable distribution (sarge) this problem has been fixed in
version 4.2.1-5sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 4.2.2-1.
We recommend that you upgrade your hylafax packages.


Solution : http://www.debian.org/security/2005/dsa-865
Risk factor : High';

if (description) {
 script_id(20020);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "865");
 script_cve_id("CVE-2005-3069");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA865] DSA-865-1 hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-865-1 hylafax");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hylafax', release: '', reference: '4.2.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax is vulnerable in Debian .\nUpgrade to hylafax_4.2.2-1\n');
}
if (deb_check(prefix: 'hylafax-client', release: '3.0', reference: '4.1.1-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-client is vulnerable in Debian 3.0.\nUpgrade to hylafax-client_4.1.1-3.2\n');
}
if (deb_check(prefix: 'hylafax-doc', release: '3.0', reference: '4.1.1-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-doc is vulnerable in Debian 3.0.\nUpgrade to hylafax-doc_4.1.1-3.2\n');
}
if (deb_check(prefix: 'hylafax-server', release: '3.0', reference: '4.1.1-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-server is vulnerable in Debian 3.0.\nUpgrade to hylafax-server_4.1.1-3.2\n');
}
if (deb_check(prefix: 'hylafax-client', release: '3.1', reference: '4.2.1-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-client is vulnerable in Debian 3.1.\nUpgrade to hylafax-client_4.2.1-5sarge1\n');
}
if (deb_check(prefix: 'hylafax-doc', release: '3.1', reference: '4.2.1-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-doc is vulnerable in Debian 3.1.\nUpgrade to hylafax-doc_4.2.1-5sarge1\n');
}
if (deb_check(prefix: 'hylafax-server', release: '3.1', reference: '4.2.1-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-server is vulnerable in Debian 3.1.\nUpgrade to hylafax-server_4.2.1-5sarge1\n');
}
if (deb_check(prefix: 'hylafax', release: '3.1', reference: '4.2.1-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax is vulnerable in Debian sarge.\nUpgrade to hylafax_4.2.1-5sarge1\n');
}
if (deb_check(prefix: 'hylafax', release: '3.0', reference: '4.1.1-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax is vulnerable in Debian woody.\nUpgrade to hylafax_4.1.1-3.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
