# This script was automatically generated from the dsa-592
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered a
format string vulnerability in ez-ipupdate, a client for many dynamic
DNS services.  This problem can only be exploited if ez-ipupdate is
running in daemon mode (most likely) with many but not all service
types.
For the stable distribution (woody) this problem has been fixed in
version 3.0.11b5-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 3.0.11b8-8.
We recommend that you upgrade your ez-ipupdate package.


Solution : http://www.debian.org/security/2004/dsa-592
Risk factor : High';

if (description) {
 script_id(15727);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "592");
 script_cve_id("CVE-2004-0980");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA592] DSA-592-1 ez-ipupdate");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-592-1 ez-ipupdate");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ez-ipupdate', release: '3.0', reference: '3.0.11b5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ez-ipupdate is vulnerable in Debian 3.0.\nUpgrade to ez-ipupdate_3.0.11b5-1woody2\n');
}
if (deb_check(prefix: 'ez-ipupdate', release: '3.1', reference: '3.0.11b8-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ez-ipupdate is vulnerable in Debian 3.1.\nUpgrade to ez-ipupdate_3.0.11b8-8\n');
}
if (deb_check(prefix: 'ez-ipupdate', release: '3.0', reference: '3.0.11b5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ez-ipupdate is vulnerable in Debian woody.\nUpgrade to ez-ipupdate_3.0.11b5-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
