# This script was automatically generated from the dsa-680
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Michael Krax discovered a cross site scripting vulnerability in
ht://dig, a web search system for an intranet or small internet.
For the stable distribution (woody) this problem has been fixed in
version 3.1.6-3woody1.
For the unstable distribution (sid) this problem has been fixed in
version 3.1.6-11.
We recommend that you upgrade your htdig package.


Solution : http://www.debian.org/security/2005/dsa-680
Risk factor : High';

if (description) {
 script_id(16391);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "680");
 script_cve_id("CVE-2005-0085");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA680] DSA-680-1 htdig");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-680-1 htdig");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'htdig', release: '3.0', reference: '3.1.6-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htdig is vulnerable in Debian 3.0.\nUpgrade to htdig_3.1.6-3woody1\n');
}
if (deb_check(prefix: 'htdig-doc', release: '3.0', reference: '3.1.6-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htdig-doc is vulnerable in Debian 3.0.\nUpgrade to htdig-doc_3.1.6-3woody1\n');
}
if (deb_check(prefix: 'htdig', release: '3.1', reference: '3.1.6-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htdig is vulnerable in Debian 3.1.\nUpgrade to htdig_3.1.6-11\n');
}
if (deb_check(prefix: 'htdig', release: '3.0', reference: '3.1.6-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htdig is vulnerable in Debian woody.\nUpgrade to htdig_3.1.6-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
