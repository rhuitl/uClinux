# This script was automatically generated from the dsa-387
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
gopherd, a gopher server from the University of Minnesota, contains a
number of buffer overflows which could be exploited by a remote
attacker to execute arbitrary code with the privileges of the gopherd
process (the "gopher" user by default).
For the stable distribution (woody) this problem has been fixed in
version 3.0.3woody1.
This program has been removed from the unstable distribution (sid).
gopherd is deprecated, and users are recommended to use PyGopherd instead.
We recommend that you update your gopherd package.


Solution : http://www.debian.org/security/2003/dsa-387
Risk factor : High';

if (description) {
 script_id(15224);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "387");
 script_cve_id("CVE-2003-0805");
 script_bugtraq_id(8167, 8168, 8283);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA387] DSA-387-1 gopher");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-387-1 gopher");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gopher', release: '3.0', reference: '3.0.3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian 3.0.\nUpgrade to gopher_3.0.3woody1\n');
}
if (deb_check(prefix: 'gopherd', release: '3.0', reference: '3.0.3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopherd is vulnerable in Debian 3.0.\nUpgrade to gopherd_3.0.3woody1\n');
}
if (deb_check(prefix: 'gopher', release: '3.0', reference: '3.0.3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian woody.\nUpgrade to gopher_3.0.3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
