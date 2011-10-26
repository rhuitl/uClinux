# This script was automatically generated from the dsa-809
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Certain aborted requests that trigger an assertion in squid, the
popular WWW proxy cache, may allow remote attackers to cause a denial
of service.  This update also fixes a regression caused by
DSA 751.
For completeness below is the original advisory text:
Several vulnerabilities have been discovered in Squid, the popular WWW
proxy cache.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Certain aborted requests that trigger an assert may allow remote
    attackers to cause a denial of service.
    Specially crafted requests can cause a denial of service.
For the oldstable distribution (woody) this problem has been fixed in
version 2.4.6-2woody10.
For the stable distribution (sarge) these problems have been fixed in
version 2.5.9-10sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2.5.10-5.
We recommend that you upgrade your squid package.


Solution : http://www.debian.org/security/2005/dsa-809
Risk factor : High';

if (description) {
 script_id(19684);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "809");
 script_cve_id("CVE-2005-2794", "CVE-2005-2796");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA809] DSA-809-2 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-809-2 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '', reference: '2.5.10-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian .\nUpgrade to squid_2.5.10-5\n');
}
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.0.\nUpgrade to squid_2.4.6-2woody10\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.0.\nUpgrade to squid-cgi_2.4.6-2woody10\n');
}
if (deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.0.\nUpgrade to squidclient_2.4.6-2woody10\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.1.\nUpgrade to squid_2.5.9-10sarge1\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.1', reference: '2.5.9-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.1.\nUpgrade to squid-cgi_2.5.9-10sarge1\n');
}
if (deb_check(prefix: 'squid-common', release: '3.1', reference: '2.5.9-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-common is vulnerable in Debian 3.1.\nUpgrade to squid-common_2.5.9-10sarge1\n');
}
if (deb_check(prefix: 'squidclient', release: '3.1', reference: '2.5.9-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.1.\nUpgrade to squidclient_2.5.9-10sarge1\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian sarge.\nUpgrade to squid_2.5.9-10sarge1\n');
}
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian woody.\nUpgrade to squid_2.4.6-2woody10\n');
}
if (w) { security_hole(port: 0, data: desc); }
