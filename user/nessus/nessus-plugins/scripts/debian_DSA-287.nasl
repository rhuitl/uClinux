# This script was automatically generated from the dsa-287
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Timo Sirainen discovered several problems in EPIC, a popular client
for Internet Relay Chat (IRC).  A malicious server could craft special
reply strings, triggering the client to write beyond buffer
boundaries.  This could lead to a denial of service if the client only
crashes, but may also lead to executing of arbitrary code under the
user id of the chatting user.
For the stable distribution (woody) these problems have been fixed in
version 3.004-17.1.
For the old stable distribution (potato) these problems have been
fixed in version 3.004-16.1.
For the unstable distribution (sid) these problems have been fixed in
version 3.004-19.
We recommend that you upgrade your EPIC package.


Solution : http://www.debian.org/security/2003/dsa-287
Risk factor : High';

if (description) {
 script_id(15124);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "287");
 script_cve_id("CVE-2003-0324");
 script_bugtraq_id(7091, 7103);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA287] DSA-287-1 epic");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-287-1 epic");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'epic', release: '2.2', reference: '3.004-16.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic is vulnerable in Debian 2.2.\nUpgrade to epic_3.004-16.1\n');
}
if (deb_check(prefix: 'epic', release: '3.0', reference: '3.004-17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic is vulnerable in Debian 3.0.\nUpgrade to epic_3.004-17.1\n');
}
if (deb_check(prefix: 'epic', release: '3.1', reference: '3.004-19')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic is vulnerable in Debian 3.1.\nUpgrade to epic_3.004-19\n');
}
if (deb_check(prefix: 'epic', release: '2.2', reference: '3.004-16.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic is vulnerable in Debian potato.\nUpgrade to epic_3.004-16.1\n');
}
if (deb_check(prefix: 'epic', release: '3.0', reference: '3.004-17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic is vulnerable in Debian woody.\nUpgrade to epic_3.004-17.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
