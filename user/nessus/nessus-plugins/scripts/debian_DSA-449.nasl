# This script was automatically generated from the dsa-449
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered two format string bugs (CVE-2004-0104) and
two buffer overflow bugs (CVE-2004-0105) in metamail, an
implementation of MIME.  An attacker could create a carefully-crafted
mail message which will execute arbitrary code as the victim when it
is opened and parsed through metamail.
We have been devoting some effort to trying to avoid shipping metamail
in the future.  It became unmaintainable and these are probably not
the last of the vulnerabilities.
For the stable distribution (woody) these problems have been fixed in
version 2.7-45woody.2.
For the unstable distribution (sid) these problems will be fixed in
version 2.7-45.2.
We recommend that you upgrade your metamail package.


Solution : http://www.debian.org/security/2004/dsa-449
Risk factor : High';

if (description) {
 script_id(15286);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "449");
 script_cve_id("CVE-2004-0104", "CVE-2004-0105");
 script_bugtraq_id(9692);
 script_xref(name: "CERT", value: "513062");
 script_xref(name: "CERT", value: "518518");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA449] DSA-449-1 metamail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-449-1 metamail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'metamail', release: '3.0', reference: '2.7-45woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metamail is vulnerable in Debian 3.0.\nUpgrade to metamail_2.7-45woody.2\n');
}
if (deb_check(prefix: 'metamail', release: '3.1', reference: '2.7-45.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metamail is vulnerable in Debian 3.1.\nUpgrade to metamail_2.7-45.2\n');
}
if (deb_check(prefix: 'metamail', release: '3.0', reference: '2.7-45woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metamail is vulnerable in Debian woody.\nUpgrade to metamail_2.7-45woody.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
