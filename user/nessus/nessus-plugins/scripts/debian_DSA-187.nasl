# This script was automatically generated from the dsa-187
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
According to David Wagner, iDEFENSE and the Apache HTTP Server
Project, several remotely exploitable vulnerabilities have been found
in the Apache package, a commonly used webserver.  These
vulnerabilities could allow an attacker to enact a denial of service
against a server or execute a cross scripting attack.  The Common
Vulnerabilities and Exposures (CVE) project identified the following
vulnerabilities:
   This is the same vulnerability as CVE-2002-1233, which was fixed in
   potato already but got lost later and was never applied upstream.
These problems have been fixed in version 1.3.26-0woody3 for the
current stable distribution (woody) and in 1.3.9-14.3 for the old
stable distribution (potato).  Corrected packages for the unstable
distribution (sid) are expected soon.
We recommend that you upgrade your Apache package immediately.


Solution : http://www.debian.org/security/2002/dsa-187
Risk factor : High';

if (description) {
 script_id(15024);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "187");
 script_cve_id("CVE-2001-0131", "CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1233");
 script_bugtraq_id(2182, 5847, 5884, 5887, 5995);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA187] DSA-187-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-187-1 apache");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache', release: '2.2', reference: '1.3.9-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 2.2.\nUpgrade to apache_1.3.9-14.3\n');
}
if (deb_check(prefix: 'apache-common', release: '2.2', reference: '1.3.9-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-common is vulnerable in Debian 2.2.\nUpgrade to apache-common_1.3.9-14.3\n');
}
if (deb_check(prefix: 'apache-dev', release: '2.2', reference: '1.3.9-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dev is vulnerable in Debian 2.2.\nUpgrade to apache-dev_1.3.9-14.3\n');
}
if (deb_check(prefix: 'apache-doc', release: '2.2', reference: '1.3.9-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-doc is vulnerable in Debian 2.2.\nUpgrade to apache-doc_1.3.9-14.3\n');
}
if (deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 3.0.\nUpgrade to apache_1.3.26-0woody3\n');
}
if (deb_check(prefix: 'apache-common', release: '3.0', reference: '1.3.26-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-common is vulnerable in Debian 3.0.\nUpgrade to apache-common_1.3.26-0woody3\n');
}
if (deb_check(prefix: 'apache-dev', release: '3.0', reference: '1.3.26-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dev is vulnerable in Debian 3.0.\nUpgrade to apache-dev_1.3.26-0woody3\n');
}
if (deb_check(prefix: 'apache-doc', release: '3.0', reference: '1.3.26-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-doc is vulnerable in Debian 3.0.\nUpgrade to apache-doc_1.3.26-0woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
