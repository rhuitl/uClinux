# This script was automatically generated from the dsa-1000
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Gunnar Wolf noticed that the correction for the following problem was
not complete and requires an update.  For completeness we\'re
providing the original problem description:
An algorithm weakness has been discovered in Apache2::Request, the
generic request library for Apache2 which can be exploited remotely
and cause a denial of service via CPU consumption.
The old stable distribution (woody) does not contain this package.
For the stable distribution (sarge) this problem has been fixed in
version 2.04-dev-1sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 2.07-1.
We recommend that you upgrade your libapreq2, libapache2-mod-apreq2
and libapache2-request-perl packages.


Solution : http://www.debian.org/security/2006/dsa-1000
Risk factor : High';

if (description) {
 script_id(22542);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1000");
 script_cve_id("CVE-2006-0042");
 script_bugtraq_id(16710);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1000] DSA-1000-2 libapreq2-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1000-2 libapreq2-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapreq2-perl', release: '', reference: '2.07-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapreq2-perl is vulnerable in Debian .\nUpgrade to libapreq2-perl_2.07-1\n');
}
if (deb_check(prefix: 'libapache2-request-perl', release: '3.1', reference: '2.04-dev-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache2-request-perl is vulnerable in Debian 3.1.\nUpgrade to libapache2-request-perl_2.04-dev-1sarge2\n');
}
if (deb_check(prefix: 'libapreq2-perl', release: '3.1', reference: '2.04-dev-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapreq2-perl is vulnerable in Debian sarge.\nUpgrade to libapreq2-perl_2.04-dev-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
