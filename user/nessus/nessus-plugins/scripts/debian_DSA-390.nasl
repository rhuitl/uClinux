# This script was automatically generated from the dsa-390
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a buffer overflow in marbles, when processing
the HOME environment variable.  This vulnerability could be exploited
by a local user to gain gid \'games\'.
For the current stable distribution (woody) this problem has been fixed
in version 1.0.2-1woody1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your marbles package.


Solution : http://www.debian.org/security/2003/dsa-390
Risk factor : High';

if (description) {
 script_id(15227);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "390");
 script_cve_id("CVE-2003-0830");
 script_bugtraq_id(8710);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA390] DSA-390-1 marbles");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-390-1 marbles");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'marbles', release: '3.0', reference: '1.0.2-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package marbles is vulnerable in Debian 3.0.\nUpgrade to marbles_1.0.2-1woody1\n');
}
if (deb_check(prefix: 'marbles', release: '3.0', reference: '1.0.2-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package marbles is vulnerable in Debian woody.\nUpgrade to marbles_1.0.2-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
