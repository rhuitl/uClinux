# This script was automatically generated from the dsa-402
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A security-related problem has been discovered in minimalist, a
mailing list manager, which allows a remote attacker to execute
arbitrary commands.
For the stable distribution (woody) this problem has been fixed in
version 2.2-4.
For the unstable distribution (sid) this problem has been fixed in
version 2.4-1.
We recommend that you upgrade your minimalist package.


Solution : http://www.debian.org/security/2003/dsa-402
Risk factor : High';

if (description) {
 script_id(15239);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "402");
 script_cve_id("CVE-2003-0902");
 script_bugtraq_id(9049);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA402] DSA-402-1 minimalist");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-402-1 minimalist");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'minimalist', release: '3.0', reference: '2.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package minimalist is vulnerable in Debian 3.0.\nUpgrade to minimalist_2.2-4\n');
}
if (deb_check(prefix: 'minimalist', release: '3.1', reference: '2.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package minimalist is vulnerable in Debian 3.1.\nUpgrade to minimalist_2.4-1\n');
}
if (deb_check(prefix: 'minimalist', release: '3.0', reference: '2.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package minimalist is vulnerable in Debian woody.\nUpgrade to minimalist_2.2-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
