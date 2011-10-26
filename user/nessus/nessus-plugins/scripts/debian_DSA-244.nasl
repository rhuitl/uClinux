# This script was automatically generated from the dsa-244
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Dan Jacobson noticed a problem in noffle, an offline news server, that
leads to a segmentation fault.  It is not yet clear whether this
problem is exploitable.  However, if it is, a remote attacker could
trigger arbitrary code execution under the user that calls noffle,
probably news.
For the stable distribution (woody) this problem has been fixed in
version 1.0.1-1.1.
The old stable distribution (potato) does not contain a noffle
package.
For the unstable distribution (sid) this problem has been fixed in
version 1.1.2-1.
We recommend that you upgrade your noffle package.


Solution : http://www.debian.org/security/2003/dsa-244
Risk factor : High';

if (description) {
 script_id(15081);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "244");
 script_cve_id("CVE-2003-0037");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA244] DSA-244-1 noffle");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-244-1 noffle");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'noffle', release: '3.0', reference: '1.0.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package noffle is vulnerable in Debian 3.0.\nUpgrade to noffle_1.0.1-1.1\n');
}
if (deb_check(prefix: 'noffle', release: '3.1', reference: '1.1.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package noffle is vulnerable in Debian 3.1.\nUpgrade to noffle_1.1.2-1\n');
}
if (deb_check(prefix: 'noffle', release: '3.0', reference: '1.0.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package noffle is vulnerable in Debian woody.\nUpgrade to noffle_1.0.1-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
