# This script was automatically generated from the dsa-576
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security vulnerabilities have been discovered in Squid, the
internet object cache, the popular WWW proxy cache.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    It is possible to bypass access lists and scan arbitrary hosts and
    ports in the network through cachemgr.cgi, which is installed by
    default.  This update disables this feature and introduces a
    configuration file (/etc/squid/cachemgr.conf) to control
    this behavior.
    The asn_parse_header function (asn1.c) in the SNMP module for
    Squid allows remote attackers to cause a denial of service via
    certain SNMP packets with negative length fields that causes a
    memory allocation error.
For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody4.
For the unstable distribution (sid) these problems have been fixed in
version 2.5.7-1.
We recommend that you upgrade your squid package.


Solution : http://www.debian.org/security/2004/dsa-576
Risk factor : High';

if (description) {
 script_id(15674);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "576");
 script_cve_id("CVE-2004-0918", "CVE-1999-0710");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA576] DSA-576-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-576-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.0.\nUpgrade to squid_2.4.6-2woody4\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.0.\nUpgrade to squid-cgi_2.4.6-2woody4\n');
}
if (deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.0.\nUpgrade to squidclient_2.4.6-2woody4\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.7-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.1.\nUpgrade to squid_2.5.7-1\n');
}
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian woody.\nUpgrade to squid_2.4.6-2woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
