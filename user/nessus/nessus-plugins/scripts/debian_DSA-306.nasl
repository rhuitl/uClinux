# This script was automatically generated from the dsa-306
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Timo Sirainen discovered several problems in BitchX, a popular client
for Internet Relay Chat (IRC).  A malicious server could craft special
reply strings, triggering the client to write beyond buffer boundaries
or allocate a negative amount of memory.  This could lead to a denial
of service if the client only crashes, but may also lead to executing
of arbitrary code under the user id of the chatting user.
For the stable distribution (woody) these problems have been fixed in
version 1.0-0c19-1.1.
For the old stable distribution (potato) these problems have been
fixed in version 1.0-0c16-2.1.
For the unstable distribution (sid) these problems have been fixed in
version 1.0-0c19-8.
We recommend that you upgrade your BitchX package.


Solution : http://www.debian.org/security/2003/dsa-306
Risk factor : High';

if (description) {
 script_id(15143);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "306");
 script_cve_id("CVE-2003-0321", "CVE-2003-0322", "CVE-2003-0328");
 script_bugtraq_id(7096, 7097, 7099, 7100);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA306] DSA-306-1 ircii-pana");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-306-1 ircii-pana");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bitchx', release: '2.2', reference: '1.0-0c16-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bitchx is vulnerable in Debian 2.2.\nUpgrade to bitchx_1.0-0c16-2.1\n');
}
if (deb_check(prefix: 'bitchx-gtk', release: '2.2', reference: '1.0-0c16-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bitchx-gtk is vulnerable in Debian 2.2.\nUpgrade to bitchx-gtk_1.0-0c16-2.1\n');
}
if (deb_check(prefix: 'bitchx', release: '3.0', reference: '1.0-0c19-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bitchx is vulnerable in Debian 3.0.\nUpgrade to bitchx_1.0-0c19-1.1\n');
}
if (deb_check(prefix: 'bitchx-dev', release: '3.0', reference: '1.0-0c19-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bitchx-dev is vulnerable in Debian 3.0.\nUpgrade to bitchx-dev_1.0-0c19-1.1\n');
}
if (deb_check(prefix: 'bitchx-gtk', release: '3.0', reference: '1.0-0c19-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bitchx-gtk is vulnerable in Debian 3.0.\nUpgrade to bitchx-gtk_1.0-0c19-1.1\n');
}
if (deb_check(prefix: 'bitchx-ssl', release: '3.0', reference: '1.0-0c19-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bitchx-ssl is vulnerable in Debian 3.0.\nUpgrade to bitchx-ssl_1.0-0c19-1.1\n');
}
if (deb_check(prefix: 'ircii-pana', release: '3.1', reference: '1.0-0c19-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ircii-pana is vulnerable in Debian 3.1.\nUpgrade to ircii-pana_1.0-0c19-8\n');
}
if (deb_check(prefix: 'ircii-pana', release: '2.2', reference: '1.0-0c16-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ircii-pana is vulnerable in Debian potato.\nUpgrade to ircii-pana_1.0-0c16-2.1\n');
}
if (deb_check(prefix: 'ircii-pana', release: '3.0', reference: '1.0-0c19-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ircii-pana is vulnerable in Debian woody.\nUpgrade to ircii-pana_1.0-0c19-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
