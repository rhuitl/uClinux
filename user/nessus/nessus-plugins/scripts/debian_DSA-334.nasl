# This script was automatically generated from the dsa-334
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered several buffer overflows in xgalaga, a game,
which can be triggered by a long HOME environment variable.  This
vulnerability could be exploited by a local attacker to gain gid
\'games\'.
For the stable distribution (woody) this problem has been fixed in
version 2.0.34-19woody1.
For the unstable distribution (sid) this problem is fixed in version
2.0.34-22.
We recommend that you update your xgalaga package.


Solution : http://www.debian.org/security/2003/dsa-334
Risk factor : High';

if (description) {
 script_id(15171);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "334");
 script_cve_id("CVE-2003-0454");
 script_bugtraq_id(8058);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA334] DSA-334-1 xgalaga");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-334-1 xgalaga");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xgalaga', release: '3.0', reference: '2.0.34-19woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xgalaga is vulnerable in Debian 3.0.\nUpgrade to xgalaga_2.0.34-19woody1\n');
}
if (deb_check(prefix: 'xgalaga', release: '3.1', reference: '2.0.34-22')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xgalaga is vulnerable in Debian 3.1.\nUpgrade to xgalaga_2.0.34-22\n');
}
if (deb_check(prefix: 'xgalaga', release: '3.0', reference: '2.0.34-19woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xgalaga is vulnerable in Debian woody.\nUpgrade to xgalaga_2.0.34-19woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
