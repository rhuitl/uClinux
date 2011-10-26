# This script was automatically generated from the dsa-1108
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It was discovered that the mutt mail reader performs insufficient
validation of values returned from an IMAP server, which might overflow
a buffer and potentially lead to the injection of arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 1.5.9-2sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 1.5.11+cvs20060403-2.
We recommend that you upgrade your mutt package.


Solution : http://www.debian.org/security/2006/dsa-1108
Risk factor : High';

if (description) {
 script_id(22650);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1108");
 script_cve_id("CVE-2006-3242");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1108] DSA-1108-1 mutt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1108-1 mutt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mutt', release: '', reference: '1.5.11+cvs20060403-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian .\nUpgrade to mutt_1.5.11+cvs20060403-2\n');
}
if (deb_check(prefix: 'mutt', release: '3.1', reference: '1.5.9-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian 3.1.\nUpgrade to mutt_1.5.9-2sarge2\n');
}
if (deb_check(prefix: 'mutt', release: '3.1', reference: '1.5.9-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian sarge.\nUpgrade to mutt_1.5.9-2sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
