# This script was automatically generated from the dsa-337
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Viliam Holub discovered a bug in gtksee whereby, when loading PNG
images of certain color depths, gtksee would overflow a heap-allocated
buffer.  This vulnerability could be exploited by an attacker using a
carefully constructed PNG image to execute arbitrary code when the
victim loads the file in gtksee.
For the stable distribution (woody) this problem has been fixed in
version 0.5.0-6.
For the unstable distribution (sid) this problem will be fixed soon.
Refer to Debian bug #76346.
We recommend that you update your gtksee package.


Solution : http://www.debian.org/security/2003/dsa-337
Risk factor : High';

if (description) {
 script_id(15174);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "337");
 script_cve_id("CVE-2003-0444");
 script_bugtraq_id(8061);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA337] DSA-337-1 gtksee");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-337-1 gtksee");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gtksee', release: '3.0', reference: '0.5.0-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtksee is vulnerable in Debian 3.0.\nUpgrade to gtksee_0.5.0-6\n');
}
if (deb_check(prefix: 'gtksee', release: '3.0', reference: '0.5.0-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtksee is vulnerable in Debian woody.\nUpgrade to gtksee_0.5.0-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
