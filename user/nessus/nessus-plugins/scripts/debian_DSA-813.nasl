# This script was automatically generated from the dsa-813
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in libgadu which is also part of
centericq, a text-mode multi-protocol instant messenger client.  The
Common Vulnerabilities and Exposures project identifies the following
problems:
    Multiple integer signedness errors may allow remote attackers to
    cause a denial of service or execute arbitrary code.
    Memory alignment errors may allows remote attackers to cause a
    denial of service on certain architectures such as sparc.
    Several endianess errors may allow remote attackers to cause a
    denial of service.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 4.20.0-1sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 4.20.0-9.
We recommend that you upgrade your centericq package.


Solution : http://www.debian.org/security/2005/dsa-813
Risk factor : High';

if (description) {
 script_id(19709);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "813");
 script_cve_id("CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
 script_bugtraq_id(14415);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA813] DSA-813-1 centericq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-813-1 centericq");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'centericq', release: '', reference: '4.20.0-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian .\nUpgrade to centericq_4.20.0-9\n');
}
if (deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian 3.1.\nUpgrade to centericq_4.20.0-1sarge2\n');
}
if (deb_check(prefix: 'centericq-common', release: '3.1', reference: '4.20.0-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-common is vulnerable in Debian 3.1.\nUpgrade to centericq-common_4.20.0-1sarge2\n');
}
if (deb_check(prefix: 'centericq-fribidi', release: '3.1', reference: '4.20.0-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-fribidi is vulnerable in Debian 3.1.\nUpgrade to centericq-fribidi_4.20.0-1sarge2\n');
}
if (deb_check(prefix: 'centericq-utf8', release: '3.1', reference: '4.20.0-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-utf8 is vulnerable in Debian 3.1.\nUpgrade to centericq-utf8_4.20.0-1sarge2\n');
}
if (deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian sarge.\nUpgrade to centericq_4.20.0-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
