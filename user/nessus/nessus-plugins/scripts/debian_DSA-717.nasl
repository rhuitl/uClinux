# This script was automatically generated from the dsa-717
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security relevant problems have been discovered in lsh, the
alternative secure shell v2 (SSH2) protocol server.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    Bennett Todd discovered a heap buffer overflow in lshd which could
    lead to the execution of arbitrary code.
    Niels Möller discovered a denial of service condition in lshd.
For the stable distribution (woody) these problems have been fixed in
version 1.2.5-2woody3.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.1-2.
We recommend that you upgrade your lsh-server package.


Solution : http://www.debian.org/security/2005/dsa-717
Risk factor : High';

if (description) {
 script_id(18153);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "717");
 script_cve_id("CVE-2003-0826", "CVE-2005-0814");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA717] DSA-717-1 lsh-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-717-1 lsh-utils");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lsh-client', release: '3.0', reference: '1.2.5-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-client is vulnerable in Debian 3.0.\nUpgrade to lsh-client_1.2.5-2woody3\n');
}
if (deb_check(prefix: 'lsh-server', release: '3.0', reference: '1.2.5-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-server is vulnerable in Debian 3.0.\nUpgrade to lsh-server_1.2.5-2woody3\n');
}
if (deb_check(prefix: 'lsh-utils', release: '3.0', reference: '1.2.5-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-utils is vulnerable in Debian 3.0.\nUpgrade to lsh-utils_1.2.5-2woody3\n');
}
if (deb_check(prefix: 'lsh-utils-doc', release: '3.0', reference: '1.2.5-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-utils-doc is vulnerable in Debian 3.0.\nUpgrade to lsh-utils-doc_1.2.5-2woody3\n');
}
if (deb_check(prefix: 'lsh-utils', release: '3.1', reference: '2.0.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-utils is vulnerable in Debian 3.1.\nUpgrade to lsh-utils_2.0.1-2\n');
}
if (deb_check(prefix: 'lsh-utils', release: '3.0', reference: '1.2.5-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-utils is vulnerable in Debian woody.\nUpgrade to lsh-utils_1.2.5-2woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
