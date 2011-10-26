# This script was automatically generated from the dsa-751
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The upstream developers have discovered a bug in the DNS lookup code
of Squid, the popular WWW proxy cache.  When the DNS client UDP port
(assigned by the operating system at startup) is unfiltered and the
network is not protected from IP spoofing, malicious users can spoof
DNS lookups which could result in users being redirected to arbitrary
web sites.
For the old stable distribution (woody) this problem has been fixed in
version 2.4.6-2woody9.
For the stable distribution (sarge) this problem has already been
fixed in version 2.5.9-9.
For the unstable distribution (sid) this problem has already been
fixed in version 2.5.9-9.
We recommend that you upgrade your squid package.


Solution : http://www.debian.org/security/2005/dsa-751
Risk factor : High';

if (description) {
 script_id(18667);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "751");
 script_cve_id("CVE-2005-1519");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA751] DSA-751-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-751-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.0.\nUpgrade to squid_2.4.6-2woody9\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.0.\nUpgrade to squid-cgi_2.4.6-2woody9\n');
}
if (deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.0.\nUpgrade to squidclient_2.4.6-2woody9\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.1.\nUpgrade to squid_2.5.9-9\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian sarge.\nUpgrade to squid_2.5.9-9\n');
}
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian woody.\nUpgrade to squid_2.4.6-2woody9\n');
}
if (w) { security_hole(port: 0, data: desc); }
