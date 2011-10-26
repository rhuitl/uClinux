# This script was automatically generated from the dsa-274
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Byrial Jensen discovered a couple of off-by-one buffer overflow in the
IMAP code of Mutt, a text-oriented mail reader supporting IMAP, MIME,
GPG, PGP and threading.  This problem could potentially allow a remote
malicious IMAP server to cause a denial of service (crash) and
possibly execute arbitrary code via a specially crafted mail folder.
For the stable distribution (woody) this problem has been fixed in
version 1.3.28-2.2.
The old stable distribution (potato) is also affected by this problem
and an update will follow.
For the unstable distribution (sid) this problem has been fixed in
version 1.4.0 and above.
We recommend that you upgrade your mutt package.


Solution : http://www.debian.org/security/2003/dsa-274
Risk factor : High';

if (description) {
 script_id(15111);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "274");
 script_cve_id("CVE-2003-0167");
 script_bugtraq_id(7229);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA274] DSA-274-1 mutt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-274-1 mutt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mutt', release: '2.2', reference: '1.2.5-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian 2.2.\nUpgrade to mutt_1.2.5-5.2\n');
}
if (deb_check(prefix: 'mutt', release: '3.0', reference: '1.3.28-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian 3.0.\nUpgrade to mutt_1.3.28-2.2\n');
}
if (deb_check(prefix: 'mutt-utf8', release: '3.0', reference: '1.3.28-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt-utf8 is vulnerable in Debian 3.0.\nUpgrade to mutt-utf8_1.3.28-2.2\n');
}
if (deb_check(prefix: 'mutt', release: '3.1', reference: '1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian 3.1.\nUpgrade to mutt_1.4\n');
}
if (deb_check(prefix: 'mutt', release: '3.0', reference: '1.3.28-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian woody.\nUpgrade to mutt_1.3.28-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
