# This script was automatically generated from the dsa-884
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Mike O\'Connor discovered that the default installation of Horde3 on
Debian includes an administrator account without a password.  Already
configured installations will not be altered by this update.
The old stable distribution (woody) does not contain horde3 packages.
For the stable distribution (sarge) this problem has been fixed in
version 3.0.4-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 3.0.5-2
We recommend that you verify your horde3 admin account if you have
installed Horde3.


Solution : http://www.debian.org/security/2005/dsa-884
Risk factor : High';

if (description) {
 script_id(22750);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "884");
 script_cve_id("CVE-2005-3344");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA884] DSA-884-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-884-1 horde3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'horde3', release: '', reference: '3.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde3 is vulnerable in Debian .\nUpgrade to horde3_3.0\n');
}
if (deb_check(prefix: 'horde3', release: '3.1', reference: '3.0.4-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde3 is vulnerable in Debian 3.1.\nUpgrade to horde3_3.0.4-4sarge1\n');
}
if (deb_check(prefix: 'horde3', release: '3.1', reference: '3.0.4-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde3 is vulnerable in Debian sarge.\nUpgrade to horde3_3.0.4-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
