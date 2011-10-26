# This script was automatically generated from the dsa-268
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Core Security Technologies discovered a buffer overflow in the IMAP
code of Mutt, a text-oriented mail reader supporting IMAP, MIME, GPG,
PGP and threading.  This problem allows a remote malicious IMAP server
to cause a denial of service (crash) and possibly execute arbitrary
code via a specially crafted mail folder.
For the stable distribution (woody) this problem has been fixed in
version 1.3.28-2.1.
The old stable distribution (potato) is not affected by this problem.
For the unstable distribution (sid) this problem has been fixed in
version 1.5.4-1.
We recommend that you upgrade your mutt package.


Solution : http://www.debian.org/security/2003/dsa-268
Risk factor : High';

if (description) {
 script_id(15105);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "268");
 script_cve_id("CVE-2003-0140");
 script_bugtraq_id(7120);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA268] DSA-268-1 mutt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-268-1 mutt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mutt', release: '3.0', reference: '1.3.28-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian 3.0.\nUpgrade to mutt_1.3.28-2.1\n');
}
if (deb_check(prefix: 'mutt-utf8', release: '3.0', reference: '1.3.28-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt-utf8 is vulnerable in Debian 3.0.\nUpgrade to mutt-utf8_1.3.28-2.1\n');
}
if (deb_check(prefix: 'mutt', release: '3.1', reference: '1.5.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian 3.1.\nUpgrade to mutt_1.5.4-1\n');
}
if (deb_check(prefix: 'mutt', release: '3.0', reference: '1.3.28-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian woody.\nUpgrade to mutt_1.3.28-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
