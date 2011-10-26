# This script was automatically generated from the dsa-745
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two input validation errors were discovered in drupal and its bundled
xmlrpc module. These errors can lead to the execution of arbitrary
commands on the web server running drupal.
drupal was not included in the old stable distribution (woody).
For the current stable distribution (sarge), these problems have been
fixed in version 4.5.3-3. 
For the unstable distribution (sid), these problems have been fixed in
version 4.5.4-1.
We recommend that you upgrade your drupal package.


Solution : http://www.debian.org/security/2005/dsa-745
Risk factor : High';

if (description) {
 script_id(18655);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "745");
 script_cve_id("CVE-2005-1921", "CVE-2005-2106", "CVE-2005-2116");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA745] DSA-745-1 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-745-1 drupal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'drupal', release: '', reference: '4.5.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian .\nUpgrade to drupal_4.5.4-1\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian 3.1.\nUpgrade to drupal_4.5.3-3\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian sarge.\nUpgrade to drupal_4.5.3-3\n');
}
if (w) { security_hole(port: 0, data: desc); }
