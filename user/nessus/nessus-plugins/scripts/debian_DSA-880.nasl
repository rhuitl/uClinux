# This script was automatically generated from the dsa-880
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several cross-site scripting vulnerabilities have been discovered in
phpmyadmin, a set of PHP-scripts to administrate MySQL over the WWW.
The Common Vulnerabilities and Exposures project identifies the
following problems:
    Andreas Kerber and Michal Cihar discovered several cross-site
    scripting vulnerabilities in the error page and in the cookie
    login.
    Stefan Esser discovered missing safety checks in grab_globals.php
    that could allow an attacker to induce phpmyadmin to include an
    arbitrary local file.
    Tobias Klein discovered several cross-site scripting
    vulnerabilities that could allow attackers to inject arbitrary
    HTML or client-side scripting.
The version in the old stable distribution (woody) has probably its
own flaws and is not easily fixable without a full audit and patch
session.  The easier way is to upgrade it from woody to sarge.
For the stable distribution (sarge) these problems have been fixed in
version 2.6.2-3sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2.6.4-pl3-1.
We recommend that you upgrade your phpmyadmin package.


Solution : http://www.debian.org/security/2005/dsa-880
Risk factor : High';

if (description) {
 script_id(22746);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "880");
 script_cve_id("CVE-2005-2869", "CVE-2005-3300", "CVE-2005-3301");
 script_bugtraq_id(15169);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA880] DSA-880-1 phpmyadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-880-1 phpmyadmin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpmyadmin', release: '', reference: '2.6.4-pl3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpmyadmin is vulnerable in Debian .\nUpgrade to phpmyadmin_2.6.4-pl3-1\n');
}
if (deb_check(prefix: 'phpmyadmin', release: '3.1', reference: '2.6.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpmyadmin is vulnerable in Debian 3.1.\nUpgrade to phpmyadmin_2.6.2-3sarge1\n');
}
if (deb_check(prefix: 'phpmyadmin', release: '3.1', reference: '2.6.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpmyadmin is vulnerable in Debian sarge.\nUpgrade to phpmyadmin_2.6.2-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
