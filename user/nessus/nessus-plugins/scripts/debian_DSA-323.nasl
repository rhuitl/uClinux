# This script was automatically generated from the dsa-323
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jakob Lell discovered a bug in the \'noroff\' script included in noweb
whereby a temporary file was created insecurely.  During a review,
several other instances of this problem were found and fixed.  Any of
these bugs could be exploited by a local user to overwrite arbitrary
files owned by the user invoking the script.
For the stable distribution (woody) these problems have been fixed in
version 2.9a-7.3.
For old stable distribution (potato) this problem has been fixed in
version 2.9a-5.1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your noweb package.


Solution : http://www.debian.org/security/2003/dsa-323
Risk factor : High';

if (description) {
 script_id(15160);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "323");
 script_cve_id("CVE-2003-0381");
 script_bugtraq_id(7937);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA323] DSA-323-1 noweb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-323-1 noweb");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nowebm', release: '2.2', reference: '2.9a-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nowebm is vulnerable in Debian 2.2.\nUpgrade to nowebm_2.9a-5.1\n');
}
if (deb_check(prefix: 'nowebm', release: '3.0', reference: '2.9a-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nowebm is vulnerable in Debian 3.0.\nUpgrade to nowebm_2.9a-7.3\n');
}
if (deb_check(prefix: 'noweb', release: '3.0', reference: '2.9a-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package noweb is vulnerable in Debian woody.\nUpgrade to noweb_2.9a-7.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
