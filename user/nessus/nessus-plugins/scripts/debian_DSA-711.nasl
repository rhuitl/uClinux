# This script was automatically generated from the dsa-711
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Nicolas Gregoire discovered a cross-site scripting vulnerability in
info2www, a converter for info files to HTML.  A malicious person
could place a harmless looking link on the web that could cause
arbitrary commands to be executed in the browser of the victim user.
For the stable distribution (woody) this problem has been fixed in
version 1.2.2.9-20woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.2.9-23.
We recommend that you upgrade your info2www package.


Solution : http://www.debian.org/security/2005/dsa-711
Risk factor : High';

if (description) {
 script_id(18086);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "711");
 script_cve_id("CVE-2004-1341");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA711] DSA-711-1 info2www");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-711-1 info2www");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'info2www', release: '3.0', reference: '1.2.2.9-20woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package info2www is vulnerable in Debian 3.0.\nUpgrade to info2www_1.2.2.9-20woody1\n');
}
if (deb_check(prefix: 'info2www', release: '3.1', reference: '1.2.2.9-23')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package info2www is vulnerable in Debian 3.1.\nUpgrade to info2www_1.2.2.9-23\n');
}
if (deb_check(prefix: 'info2www', release: '3.0', reference: '1.2.2.9-20woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package info2www is vulnerable in Debian woody.\nUpgrade to info2www_1.2.2.9-20woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
