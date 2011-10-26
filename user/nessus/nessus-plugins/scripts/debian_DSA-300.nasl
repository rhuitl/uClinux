# This script was automatically generated from the dsa-300
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Byrial Jensen discovered a couple of off-by-one buffer overflow in the
IMAP code of Mutt, a text-oriented mail reader supporting IMAP, MIME,
GPG, PGP and threading.  This code is imported in the Balsa package.
This problem could potentially allow a remote malicious IMAP server to
cause a denial of service (crash) and possibly execute arbitrary code
via a specially crafted mail folder.
For the stable distribution (woody) this problem has been fixed in
version 1.2.4-2.2.
The old stable distribution (potato) does not seem to be affected by
this problem.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your balsa package.


Solution : http://www.debian.org/security/2003/dsa-300
Risk factor : High';

if (description) {
 script_id(15137);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "300");
 script_cve_id("CVE-2003-0167");
 script_bugtraq_id(7229);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA300] DSA-300-1 balsa");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-300-1 balsa");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'balsa', release: '3.0', reference: '1.2.4-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package balsa is vulnerable in Debian 3.0.\nUpgrade to balsa_1.2.4-2.2\n');
}
if (deb_check(prefix: 'balsa', release: '3.0', reference: '1.2.4-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package balsa is vulnerable in Debian woody.\nUpgrade to balsa_1.2.4-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
