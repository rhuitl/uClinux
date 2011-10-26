# This script was automatically generated from the dsa-1007
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '

The Drupal Security Team discovered several vulnerabilities in Drupal,
a fully-featured content management and discussion engine.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Due to missing input sanitising a remote attacker could inject
    headers of outgoing e-mail messages and use Drupal as a spam
    proxy.
    Missing input sanity checks allows attackers to inject arbitrary
    web script or HTML.
    Menu items created with the menu.module lacked access control,
    which might allow remote attackers to access administrator pages.
    Markus Petrux discovered a bug in the session fixation which may
    allow remote attackers to gain Drupal user privileges.
The old stable distribution (woody) does not contain Drupal packages.
For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-6.
For the unstable distribution (sid) these problems have been fixed in
version 4.5.8-1.
We recommend that you upgrade your drupal package.


Solution : http://www.debian.org/security/2006/dsa-1007
Risk factor : High';

if (description) {
 script_id(22549);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1007");
 script_cve_id("CVE-2006-1225", "CVE-2006-1226", "CVE-2006-1227", "CVE-2006-1228");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1007] DSA-1007-1 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1007-1 drupal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'drupal', release: '', reference: '4.5.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian .\nUpgrade to drupal_4.5.8-1\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian 3.1.\nUpgrade to drupal_4.5.3-6\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian sarge.\nUpgrade to drupal_4.5.3-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
