# This script was automatically generated from the dsa-494
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jack <"jack@rapturesecurity.org"> discovered a buffer overflow in
ident2, an implementation of the ident protocol (RFC1413), where a
buffer in the child_service function was slightly too small to hold
all of the data which could be written into it.  This vulnerability
could be exploited by a remote attacker to execute arbitrary code with
the privileges of the ident2 daemon (by default, the "identd" user).
For the current stable distribution (woody) this problem has been
fixed in version 1.03-3woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your ident2 package.


Solution : http://www.debian.org/security/2004/dsa-494
Risk factor : High';

if (description) {
 script_id(15331);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "494");
 script_cve_id("CVE-2004-0408");
 script_bugtraq_id(10192);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA494] DSA-494-1 ident2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-494-1 ident2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ident2', release: '3.0', reference: '1.03-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ident2 is vulnerable in Debian 3.0.\nUpgrade to ident2_1.03-3woody1\n');
}
if (deb_check(prefix: 'ident2', release: '3.0', reference: '1.03-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ident2 is vulnerable in Debian woody.\nUpgrade to ident2_1.03-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
