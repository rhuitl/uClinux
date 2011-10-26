# This script was automatically generated from the dsa-399
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jeremy Nelson discovered a remotely exploitable buffer overflow in
EPIC4, a popular client for Internet Relay Chat (IRC).  A malicious
server could craft a reply which triggers the client to allocate a
negative amount of memory.  This could lead to a denial of service if
the client only crashes, but may also lead to executing of arbitrary
code under the user id of the chatting user.
For the stable distribution (woody) this problem has been fixed in
version 1.1.2.20020219-2.2.
For the unstable distribution (sid) this problem has been fixed in
version 1.1.11.20030409-2.
We recommend that you upgrade your epic4 package.


Solution : http://www.debian.org/security/2003/dsa-399
Risk factor : High';

if (description) {
 script_id(15236);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "399");
 script_cve_id("CVE-2003-0328");
 script_bugtraq_id(8999);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA399] DSA-399-1 epic4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-399-1 epic4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'epic4', release: '3.0', reference: '1.1.2.20020219-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4 is vulnerable in Debian 3.0.\nUpgrade to epic4_1.1.2.20020219-2.2\n');
}
if (deb_check(prefix: 'epic4', release: '3.1', reference: '1.1.11.20030409-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4 is vulnerable in Debian 3.1.\nUpgrade to epic4_1.1.11.20030409-2\n');
}
if (deb_check(prefix: 'epic4', release: '3.0', reference: '1.1.2.20020219-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4 is vulnerable in Debian woody.\nUpgrade to epic4_1.1.2.20020219-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
