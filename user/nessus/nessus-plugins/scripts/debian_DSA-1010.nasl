# This script was automatically generated from the dsa-1010
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered that
ilohamail, a lightweight multilingual web-based IMAP/POP3 client, does
not always sanitise input provided by users which allows remote
attackers to inject arbitrary web script or HTML.
The old stable distribution (woody) does not contain an ilohamail
package.
For the stable distribution (sarge) these problems have been fixed in
version 0.8.14-0rc3sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 0.8.14-0rc3sarge1.
We recommend that you upgrade your ilohamail package.


Solution : http://www.debian.org/security/2006/dsa-1010
Risk factor : High';

if (description) {
 script_id(22552);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1010");
 script_bugtraq_id(13175);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1010] DSA-1010-1 ilohamail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1010-1 ilohamail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ilohamail', release: '', reference: '0.8.14-0rc3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ilohamail is vulnerable in Debian .\nUpgrade to ilohamail_0.8.14-0rc3sarge1\n');
}
if (deb_check(prefix: 'ilohamail', release: '3.1', reference: '0.8.14-0rc3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ilohamail is vulnerable in Debian 3.1.\nUpgrade to ilohamail_0.8.14-0rc3sarge1\n');
}
if (deb_check(prefix: 'ilohamail', release: '3.1', reference: '0.8.14-0rc3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ilohamail is vulnerable in Debian sarge.\nUpgrade to ilohamail_0.8.14-0rc3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
