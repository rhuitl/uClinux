# This script was automatically generated from the dsa-1125
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The Drupal update in DSA 1125 contained a regression. This update corrects
this flaw. For completeness, the original advisory text below:
Several remote vulnerabilities have been discovered in the Drupal web site
platform, which may lead to the execution of arbitrary web script. The
Common Vulnerabilities and Exposures project identifies the following
problems:
    A SQL injection vulnerability has been discovered in the "count" and
    "from" variables of the database interface.
    Multiple file extensions were handled incorrectly if Drupal ran on
    Apache with mod_mime enabled.
    A variation of CVE-2006-2743 was addressed as well.
    A Cross-Site-Scripting vulnerability in the upload module has been
    discovered.
    A Cross-Site-Scripting vulnerability in the taxonomy module has been
    discovered.
For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-6.1sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 4.5.8-1.1.
We recommend that you upgrade your drupal packages.


Solution : http://www.debian.org/security/2006/dsa-1125
Risk factor : High';

if (description) {
 script_id(22667);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1125");
 script_cve_id("CVE-2006-2742", "CVE-2006-2743", "CVE-2006-2831", "CVE-2006-2832", "CVE-2006-2833");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1125] DSA-1125-2 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1125-2 drupal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'drupal', release: '', reference: '4.5.8-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian .\nUpgrade to drupal_4.5.8-1.1\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-6.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian 3.1.\nUpgrade to drupal_4.5.3-6.1sarge2\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-6.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian sarge.\nUpgrade to drupal_4.5.3-6.1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
