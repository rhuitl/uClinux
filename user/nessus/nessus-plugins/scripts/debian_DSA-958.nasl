# This script was automatically generated from the dsa-958
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in drupal, a
fully-featured content management/discussion engine.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    Several cross-site scripting vulnerabilities allow remote
    attackers to inject arbitrary web script or HTML.
    When running on PHP5, Drupal does not correctly enforce user
    privileges, which allows remote attackers to bypass the "access
    user profiles" permission.
    An interpretation conflict allows remote authenticated users to
    inject arbitrary web script or HTML via HTML in a file with a GIF
    or JPEG file extension.
The old stable distribution (woody) does not contain drupal packages.
For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-5.
For the unstable distribution (sid) these problems have been fixed in
version 4.5.6-1.
We recommend that you upgrade your drupal package.


Solution : http://www.debian.org/security/2006/dsa-958
Risk factor : High';

if (description) {
 script_id(22824);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "958");
 script_cve_id("CVE-2005-3973", "CVE-2005-3974", "CVE-2005-3975");
 script_bugtraq_id(15663, 15674, 15677);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA958] DSA-958-1 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-958-1 drupal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'drupal', release: '', reference: '4.5.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian .\nUpgrade to drupal_4.5.6-1\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian 3.1.\nUpgrade to drupal_4.5.3-5\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian sarge.\nUpgrade to drupal_4.5.3-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
