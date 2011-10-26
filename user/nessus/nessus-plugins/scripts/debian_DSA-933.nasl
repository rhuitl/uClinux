# This script was automatically generated from the dsa-933
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Patrice Fournier found that hylafax passes unsanitized user data in the
notify script, allowing users with the ability to submit jobs to run
arbitrary commands  with the privileges of the hylafax server.
For the old stable distribution (woody) this problem has been fixed in
version 4.1.1-4woody1.
For the stable distribution (sarge) this problem has been fixed in
version 4.2.1-5sarge3.
For the unstable distribution the problem has been fixed in version
4.2.4-2.
We recommend that you upgrade your hylafax package.


Solution : http://www.debian.org/security/2006/dsa-933
Risk factor : High';

if (description) {
 script_id(22799);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "933");
 script_cve_id("CVE-2005-3539");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA933] DSA-933-1 hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-933-1 hylafax");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hylafax-client', release: '3.0', reference: '4.1.1-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-client is vulnerable in Debian 3.0.\nUpgrade to hylafax-client_4.1.1-4woody1\n');
}
if (deb_check(prefix: 'hylafax-doc', release: '3.0', reference: '4.1.1-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-doc is vulnerable in Debian 3.0.\nUpgrade to hylafax-doc_4.1.1-4woody1\n');
}
if (deb_check(prefix: 'hylafax-server', release: '3.0', reference: '4.1.1-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-server is vulnerable in Debian 3.0.\nUpgrade to hylafax-server_4.1.1-4woody1\n');
}
if (deb_check(prefix: 'hylafax', release: '3.1', reference: '4.2.4-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax is vulnerable in Debian 3.1.\nUpgrade to hylafax_4.2.4-2\n');
}
if (deb_check(prefix: 'hylafax-client', release: '3.1', reference: '4.2.1-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-client is vulnerable in Debian 3.1.\nUpgrade to hylafax-client_4.2.1-5sarge3\n');
}
if (deb_check(prefix: 'hylafax-doc', release: '3.1', reference: '4.2.1-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-doc is vulnerable in Debian 3.1.\nUpgrade to hylafax-doc_4.2.1-5sarge3\n');
}
if (deb_check(prefix: 'hylafax-server', release: '3.1', reference: '4.2.1-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-server is vulnerable in Debian 3.1.\nUpgrade to hylafax-server_4.2.1-5sarge3\n');
}
if (deb_check(prefix: 'hylafax', release: '3.1', reference: '4.2.1-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax is vulnerable in Debian sarge.\nUpgrade to hylafax_4.2.1-5sarge3\n');
}
if (deb_check(prefix: 'hylafax', release: '3.0', reference: '4.1.1-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax is vulnerable in Debian woody.\nUpgrade to hylafax_4.1.1-4woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
