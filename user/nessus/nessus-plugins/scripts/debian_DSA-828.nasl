# This script was automatically generated from the dsa-828
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Upstream developers of squid, the popular WWW proxy cache, have
discovered that changes in the authentication scheme are not handled
properly when given certain request sequences while NTLM
authentication is in place, which may cause the daemon to restart.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.5.9-10sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 2.5.10-6.
We recommend that you upgrade your squid packages.


Solution : http://www.debian.org/security/2005/dsa-828
Risk factor : High';

if (description) {
 script_id(19797);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "828");
 script_cve_id("CVE-2005-2917");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA828] DSA-828-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-828-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '', reference: '2.5.10-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian .\nUpgrade to squid_2.5.10-6\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.1.\nUpgrade to squid_2.5.9-10sarge2\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.1', reference: '2.5.9-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.1.\nUpgrade to squid-cgi_2.5.9-10sarge2\n');
}
if (deb_check(prefix: 'squid-common', release: '3.1', reference: '2.5.9-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-common is vulnerable in Debian 3.1.\nUpgrade to squid-common_2.5.9-10sarge2\n');
}
if (deb_check(prefix: 'squidclient', release: '3.1', reference: '2.5.9-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.1.\nUpgrade to squidclient_2.5.9-10sarge2\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian sarge.\nUpgrade to squid_2.5.9-10sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
