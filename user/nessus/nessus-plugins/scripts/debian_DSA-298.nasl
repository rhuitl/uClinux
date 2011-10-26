# This script was automatically generated from the dsa-298
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Timo Sirainen discovered several problems in EPIC4, a popular client
for Internet Relay Chat (IRC).  A malicious server could craft special
reply strings, triggering the client to write beyond buffer
boundaries.  This could lead to a denial of service if the client only
crashes, but may also lead to executing of arbitrary code under the
user id of the chatting user.
For the stable distribution (woody) these problems have been fixed in
version 1.1.2.20020219-2.1.
For the old stable distribution (potato) these problems have been
fixed in version pre2.508-2.3.
For the unstable distribution (sid) these problems have been fixed in
version 1.1.11.20030409-1.
We recommend that you upgrade your EPIC4 package.


Solution : http://www.debian.org/security/2003/dsa-298
Risk factor : High';

if (description) {
 script_id(15135);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "298");
 script_cve_id("CVE-2003-0323");
 script_bugtraq_id(7093, 7094, 7095, 7098);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA298] DSA-298-1 epic4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-298-1 epic4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'epic4', release: '2.2', reference: 'pre2.508-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4 is vulnerable in Debian 2.2.\nUpgrade to epic4_pre2.508-2.3\n');
}
if (deb_check(prefix: 'epic4', release: '3.0', reference: '1.1.2.20020219-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4 is vulnerable in Debian 3.0.\nUpgrade to epic4_1.1.2.20020219-2.1\n');
}
if (deb_check(prefix: 'epic4', release: '3.1', reference: '1.1.11.20030409-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4 is vulnerable in Debian 3.1.\nUpgrade to epic4_1.1.11.20030409-1\n');
}
if (deb_check(prefix: 'epic4', release: '2.2', reference: 'pre2.508-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4 is vulnerable in Debian potato.\nUpgrade to epic4_pre2.508-2.3\n');
}
if (deb_check(prefix: 'epic4', release: '3.0', reference: '1.1.2.20020219-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4 is vulnerable in Debian woody.\nUpgrade to epic4_1.1.2.20020219-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
