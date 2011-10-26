# This script was automatically generated from the dsa-195
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
According to David Wagner, iDEFENSE and the Apache HTTP Server
Project, several vulnerabilities have been found in the Apache server
package, a commonly used webserver.  Most of the code is shared
between the Apache and Apache-Perl packages, so vulnerabilities are
shared as well.
These vulnerabilities could allow an attacker to enact a denial of
service against a server or execute a cross site scripting attack, or
steal cookies from other web site users.  The Common Vulnerabilities
and Exposures (CVE) project identified the following vulnerabilities:
These problems have been fixed in version 1.3.26-1-1.26-0woody2 for
the current stable distribution (woody), in
1.3.9-14.1-1.21.20000309-1.1 for the old stable distribution (potato)
and in version 1.3.26-1.1-1.27-3-1 for the unstable distribution
(sid).
We recommend that you upgrade your Apache-Perl package immediately.


Solution : http://www.debian.org/security/2002/dsa-195
Risk factor : High';

if (description) {
 script_id(15032);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "195");
 script_cve_id("CVE-2001-0131", "CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1233");
 script_bugtraq_id(5847, 5884, 5887, 5995);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA195] DSA-195-1 apache-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-195-1 apache-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache-perl', release: '2.2', reference: '1.3.9-14.1-1.21.20000309-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-perl is vulnerable in Debian 2.2.\nUpgrade to apache-perl_1.3.9-14.1-1.21.20000309-1.1\n');
}
if (deb_check(prefix: 'apache-perl', release: '3.0', reference: '1.3.26-1-1.26-0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-perl is vulnerable in Debian 3.0.\nUpgrade to apache-perl_1.3.26-1-1.26-0woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
