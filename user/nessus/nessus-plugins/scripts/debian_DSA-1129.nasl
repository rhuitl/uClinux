# This script was automatically generated from the dsa-1129
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar and Max Vozeler from the Debian Security Audit Project
have found several format string security bugs in osiris, a
network-wide system integrity monitor control interface.  A remote
attacker could exploit them and cause a denial of service or execute
arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 4.0.6-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 4.2.0-2.
We recommend that you upgrade your osiris packages.


Solution : http://www.debian.org/security/2006/dsa-1129
Risk factor : High';

if (description) {
 script_id(22671);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1129");
 script_cve_id("CVE-2006-3120");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1129] DSA-1129-1 osiris");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1129-1 osiris");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'osiris', release: '', reference: '4.2.0-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osiris is vulnerable in Debian .\nUpgrade to osiris_4.2.0-2\n');
}
if (deb_check(prefix: 'osiris', release: '3.1', reference: '4.0.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osiris is vulnerable in Debian 3.1.\nUpgrade to osiris_4.0.6-1sarge1\n');
}
if (deb_check(prefix: 'osirisd', release: '3.1', reference: '4.0.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osirisd is vulnerable in Debian 3.1.\nUpgrade to osirisd_4.0.6-1sarge1\n');
}
if (deb_check(prefix: 'osirismd', release: '3.1', reference: '4.0.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osirismd is vulnerable in Debian 3.1.\nUpgrade to osirismd_4.0.6-1sarge1\n');
}
if (deb_check(prefix: 'osiris', release: '3.1', reference: '4.0.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osiris is vulnerable in Debian sarge.\nUpgrade to osiris_4.0.6-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
