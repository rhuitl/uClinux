# This script was automatically generated from the dsa-188
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
According to David Wagner, iDEFENSE and the Apache HTTP Server
Project, several vulnerabilities have been found in the Apache
package, a commonly used webserver.  Most of the code is shared
between the Apache and Apache-SSL packages, so vulnerabilities are
shared as well.  These vulnerabilities could allow an attacker to
enact a denial of service against a server or execute a cross
scripting attack, or steal cookies from other web site users.
Vulnerabilities in the included legacy programs htdigest, htpasswd and
ApacheBench can be exploited when called via CGI.  Additionally the
insecure temporary file creation in htdigest and htpasswd can also be
exploited locally.  The Common Vulnerabilities and Exposures (CVE)
project identified the following vulnerabilities:
   This is the same vulnerability as CVE-2002-1233, which was fixed in
   potato already but got lost later and was never applied upstream.
   (binaries not included in apache-ssl package though)
These problems have been fixed in version 1.3.26.1+1.48-0woody3 for
the current stable distribution (woody) and in 1.3.9.13-4.2 for the
old stable distribution (potato).  Corrected packages for the unstable
distribution (sid) are expected soon.
We recommend that you upgrade your Apache-SSL package immediately.


Solution : http://www.debian.org/security/2002/dsa-188
Risk factor : High';

if (description) {
 script_id(15025);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "188");
 script_cve_id("CVE-2001-0131", "CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1233");
 script_bugtraq_id(5847, 5884, 5887, 5995);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA188] DSA-188-1 apache-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-188-1 apache-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache-ssl', release: '2.2', reference: '1.3.9.13-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-ssl is vulnerable in Debian 2.2.\nUpgrade to apache-ssl_1.3.9.13-4.2\n');
}
if (deb_check(prefix: 'apache-ssl', release: '3.0', reference: '1.3.26.1+1.48-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-ssl is vulnerable in Debian 3.0.\nUpgrade to apache-ssl_1.3.26.1+1.48-0woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
