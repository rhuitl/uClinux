# This script was automatically generated from the dsa-353
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
sup, a package used to maintain collections of files in identical
versions across machines, fails to take appropriate security
precautions when creating temporary files.  A local attacker could
exploit this vulnerability to overwrite arbitrary files with the
privileges of the user running sup.
For the stable distribution (woody) this problem has been fixed in
version 1.8-8woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.8-9.
We recommend that you update your sup package.


Solution : http://www.debian.org/security/2003/dsa-353
Risk factor : High';

if (description) {
 script_id(15190);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "353");
 script_cve_id("CVE-2003-0606");
 script_bugtraq_id(6150);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA353] DSA-353-1 sup");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-353-1 sup");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sup', release: '3.0', reference: '1.8-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sup is vulnerable in Debian 3.0.\nUpgrade to sup_1.8-8woody1\n');
}
if (deb_check(prefix: 'sup', release: '3.1', reference: '1.8-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sup is vulnerable in Debian 3.1.\nUpgrade to sup_1.8-9\n');
}
if (deb_check(prefix: 'sup', release: '3.0', reference: '1.8-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sup is vulnerable in Debian woody.\nUpgrade to sup_1.8-8woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
