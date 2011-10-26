# This script was automatically generated from the dsa-721
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Michael Bhola discovered a bug in Squid, the popular WWW proxy cache.
Squid does not trigger a fatal error when it identifies missing or
invalid ACLs in the http_access configuration, which could lead to
less restrictive ACLs than intended by the administrator.
For the stable distribution (woody) this problem has been fixed in
version 2.4.6-2woody8.
For the unstable distribution (sid) this problem has been fixed in
version 2.5.9-7.
We recommend that you upgrade your squid packages.


Solution : http://www.debian.org/security/2005/dsa-721
Risk factor : High';

if (description) {
 script_id(18242);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "721");
 script_cve_id("CVE-2005-1345");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA721] DSA-721-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-721-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.0.\nUpgrade to squid_2.4.6-2woody8\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.0.\nUpgrade to squid-cgi_2.4.6-2woody8\n');
}
if (deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.0.\nUpgrade to squidclient_2.4.6-2woody8\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.1.\nUpgrade to squid_2.5.9-7\n');
}
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian woody.\nUpgrade to squid_2.4.6-2woody8\n');
}
if (w) { security_hole(port: 0, data: desc); }
