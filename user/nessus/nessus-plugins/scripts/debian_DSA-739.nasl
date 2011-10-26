# This script was automatically generated from the dsa-739
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser discovered an input validation flaw within Trac, a wiki
and issue tracking system, that allows download/upload of files and
therefore can lead to remote code execution in some configurations.
The old stable distribution (woody) does not contain the trac package.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.1-3sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 0.8.4-1.
We recommend that you upgrade your trac package.


Solution : http://www.debian.org/security/2005/dsa-739
Risk factor : High';

if (description) {
 script_id(18631);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "739");
 script_cve_id("CVE-2005-2147");
 script_bugtraq_id(13990);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA739] DSA-739-1 trac");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-739-1 trac");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'trac', release: '', reference: '0.8.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian .\nUpgrade to trac_0.8.4-1\n');
}
if (deb_check(prefix: 'trac', release: '3.1', reference: '0.8.1-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian 3.1.\nUpgrade to trac_0.8.1-3sarge2\n');
}
if (deb_check(prefix: 'trac', release: '3.1', reference: '0.8.1-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian sarge.\nUpgrade to trac_0.8.1-3sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
