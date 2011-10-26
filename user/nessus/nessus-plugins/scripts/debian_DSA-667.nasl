# This script was automatically generated from the dsa-667
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in Squid, the internet
object cache, the popular WWW proxy cache.  The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities:
    LDAP is very forgiving about spaces in search filters and this
    could be abused to log in using several variants of the login
    name, possibly bypassing explicit access controls or confusing
    accounting.
    Cache pollution/poisoning via HTTP response splitting has been
    discovered.
    The meaning of the access controls becomes somewhat confusing if
    any of the referenced ACLs (access control lists) is declared
    empty, without any members.
    The length argument of the WCCP recvfrom() call is larger than it
    should be.  An attacker may send a larger than normal WCCP packet
    that could overflow a buffer.
For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody6.
For the unstable distribution (sid) these problems have been fixed in
version 2.5.7-7.
We recommend that you upgrade your squid package.


Solution : http://www.debian.org/security/2005/dsa-667
Risk factor : High';

if (description) {
 script_id(16341);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "667");
 script_cve_id("CVE-2005-0173", "CVE-2005-0175", "CVE-2005-0194", "CVE-2005-0211");
 script_xref(name: "CERT", value: "625878");
 script_xref(name: "CERT", value: "886006");
 script_xref(name: "CERT", value: "924198");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA667] DSA-667-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-667-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.0.\nUpgrade to squid_2.4.6-2woody6\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.0.\nUpgrade to squid-cgi_2.4.6-2woody6\n');
}
if (deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.0.\nUpgrade to squidclient_2.4.6-2woody6\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.7-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.1.\nUpgrade to squid_2.5.7-7\n');
}
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian woody.\nUpgrade to squid_2.4.6-2woody6\n');
}
if (w) { security_hole(port: 0, data: desc); }
