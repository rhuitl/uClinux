# This script was automatically generated from the dsa-840
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser of the Hardened-PHP Project reported a serious vulnerability
in the third-party XML-RPC library included with some Drupal versions.  An
attacker could execute arbitrary PHP code on a target site.  This update
pulls in the latest XML-RPC version from upstream.
The old stable distribution (woody) is not affected by this problem since
no drupal is included.
For the stable distribution (sarge) this problem has been fixed in
version 4.5.3-4.
For the unstable distribution (sid) this problem has been fixed in
version 4.5.5-1.
We recommend that you upgrade your drupal package.


Solution : http://www.debian.org/security/2005/dsa-840
Risk factor : High';

if (description) {
 script_id(19809);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "840");
 script_cve_id("CVE-2005-2498");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA840] DSA-840-1 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-840-1 drupal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'drupal', release: '', reference: '4.5.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian .\nUpgrade to drupal_4.5.5-1\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian 3.1.\nUpgrade to drupal_4.5.3-4\n');
}
if (deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package drupal is vulnerable in Debian sarge.\nUpgrade to drupal_4.5.3-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
