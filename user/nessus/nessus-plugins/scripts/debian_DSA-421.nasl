# This script was automatically generated from the dsa-421
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
David B Harris discovered a problem with mod-auth-shadow, an Apache
module which authenticates users against the system shadow password
database, where the expiration status of the user\'s account and
password were not enforced.  This vulnerability would allow an
otherwise authorized user to successfully authenticate, when the
attempt should be rejected due to the expiration parameters.
For the current stable distribution (woody) this problem has been
fixed in version 1.3-3.1woody.1
For the unstable distribution (sid) this problem has been fixed in
version 1.4-1.
We recommend that you update your mod-auth-shadow package.


Solution : http://www.debian.org/security/2004/dsa-421
Risk factor : High';

if (description) {
 script_id(15258);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "421");
 script_cve_id("CVE-2004-0041");
 script_bugtraq_id(9404);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA421] DSA-421-1 mod-auth-shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-421-1 mod-auth-shadow");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-mod-auth-shadow', release: '3.0', reference: '1.3-3.1woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-auth-shadow is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-auth-shadow_1.3-3.1woody.1\n');
}
if (deb_check(prefix: 'mod-auth-shadow', release: '3.1', reference: '1.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mod-auth-shadow is vulnerable in Debian 3.1.\nUpgrade to mod-auth-shadow_1.4-1\n');
}
if (deb_check(prefix: 'mod-auth-shadow', release: '3.0', reference: '1.3-3.1woody')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mod-auth-shadow is vulnerable in Debian woody.\nUpgrade to mod-auth-shadow_1.3-3.1woody\n');
}
if (w) { security_hole(port: 0, data: desc); }
