# This script was automatically generated from the dsa-734
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two denial of service problems have been discovered in Gaim, a
multi-protocol instant messaging client.  The Common Vulnerabilities
and Exposures project identifies the following problems:
    A malformed Yahoo filename can result in a crash of the application.
    A malformed MSN message can lead to incorrect memory allocation
    resulting in a crash of the application.
The old stable distribution (woody) does not seem to be affected.
For the stable distribution (sarge) these problems have been fixed in
version 1.2.1-1.3.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.1-1.
We recommend that you upgrade your gaim package.


Solution : http://www.debian.org/security/2005/dsa-734
Risk factor : High';

if (description) {
 script_id(18623);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "734");
 script_cve_id("CVE-2005-1269", "CVE-2005-1934");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA734] DSA-734-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-734-1 gaim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gaim', release: '', reference: '1.3.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian .\nUpgrade to gaim_1.3.1-1\n');
}
if (deb_check(prefix: 'gaim', release: '3.1', reference: '1.2.1-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian 3.1.\nUpgrade to gaim_1.2.1-1.3\n');
}
if (deb_check(prefix: 'gaim-data', release: '3.1', reference: '1.2.1-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim-data is vulnerable in Debian 3.1.\nUpgrade to gaim-data_1.2.1-1.3\n');
}
if (deb_check(prefix: 'gaim-dev', release: '3.1', reference: '1.2.1-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim-dev is vulnerable in Debian 3.1.\nUpgrade to gaim-dev_1.2.1-1.3\n');
}
if (deb_check(prefix: 'gaim', release: '3.1', reference: '1.2.1-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian sarge.\nUpgrade to gaim_1.2.1-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
