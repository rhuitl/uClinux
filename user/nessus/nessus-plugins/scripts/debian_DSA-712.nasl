# This script was automatically generated from the dsa-712
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tim Dijkstra discovered a problem during the upgrade of geneweb, a
genealogy software with web interface.  The maintainer scripts
automatically converted files without checking their permissions and
content, which could lead to the modification of arbitrary files.
For the stable distribution (woody) this problem has been fixed in
version 4.06-2woody1.
For the unstable distribution (sid) this problem has been fixed in
version 4.10-7.
We recommend that you upgrade your geneweb package.


Solution : http://www.debian.org/security/2005/dsa-712
Risk factor : High';

if (description) {
 script_id(18087);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "712");
 script_cve_id("CVE-2005-0391");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA712] DSA-712-1 geneweb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-712-1 geneweb");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'geneweb', release: '3.0', reference: '4.06-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package geneweb is vulnerable in Debian 3.0.\nUpgrade to geneweb_4.06-2woody1\n');
}
if (deb_check(prefix: 'gwtp', release: '3.0', reference: '4.06-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gwtp is vulnerable in Debian 3.0.\nUpgrade to gwtp_4.06-2woody1\n');
}
if (deb_check(prefix: 'geneweb', release: '3.1', reference: '4.10-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package geneweb is vulnerable in Debian 3.1.\nUpgrade to geneweb_4.10-7\n');
}
if (deb_check(prefix: 'geneweb', release: '3.0', reference: '4.06-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package geneweb is vulnerable in Debian woody.\nUpgrade to geneweb_4.06-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
