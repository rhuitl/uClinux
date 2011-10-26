# This script was automatically generated from the dsa-688
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Upstream developers have discovered several problems in squid, the
Internet object cache, the popular WWW proxy cache.  A remote attacker
can cause squid to crash via certain DNS responses.
For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody7.
For the unstable distribution (sid) these problems have been fixed in
version 2.5.8-3.
We recommend that you upgrade your squid package.


Solution : http://www.debian.org/security/2005/dsa-688
Risk factor : High';

if (description) {
 script_id(17196);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "688");
 script_cve_id("CVE-2005-0446");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA688] DSA-688-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-688-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.0.\nUpgrade to squid_2.4.6-2woody7\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.0.\nUpgrade to squid-cgi_2.4.6-2woody7\n');
}
if (deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.0.\nUpgrade to squidclient_2.4.6-2woody7\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.8-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.1.\nUpgrade to squid_2.5.8-3\n');
}
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian woody.\nUpgrade to squid_2.4.6-2woody7\n');
}
if (w) { security_hole(port: 0, data: desc); }
