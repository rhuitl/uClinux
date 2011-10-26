# This script was automatically generated from the dsa-1187
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jason Hoover discovered that migrationtools, a collection of scripts
to migrate user data to LDAP creates several temporary files insecurely,
which might lead to denial of service through a symlink attack.
For the stable distribution (sarge) this problem has been fixed in
version 46-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 46-2.1.
We recommend that you upgrade your migrationtools package.


Solution : http://www.debian.org/security/2006/dsa-1187
Risk factor : High';

if (description) {
 script_id(22729);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1187");
 script_cve_id("CVE-2006-0512");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1187] DSA-1187-1 migrationtools");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1187-1 migrationtools");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'migrationtools', release: '', reference: '46-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package migrationtools is vulnerable in Debian .\nUpgrade to migrationtools_46-2.1\n');
}
if (deb_check(prefix: 'migrationtools', release: '3.1', reference: '46-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package migrationtools is vulnerable in Debian 3.1.\nUpgrade to migrationtools_46-1sarge1\n');
}
if (deb_check(prefix: 'migrationtools', release: '3.1', reference: '46-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package migrationtools is vulnerable in Debian sarge.\nUpgrade to migrationtools_46-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
