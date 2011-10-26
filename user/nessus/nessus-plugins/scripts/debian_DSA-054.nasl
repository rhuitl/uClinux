# This script was automatically generated from the dsa-054
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A recent (fall 2000) security fix to cron introduced an error in giving
up privileges before invoking the editor. This was discovered by Sebastian
Krahmer from SuSE. A malicious user could easily gain root access.

This has been fixed in version 3.0pl1-57.3 (or 3.0pl1-67 for unstable).
No exploits are known to exist, but we recommend that you upgrade your
cron packages immediately.



Solution : http://www.debian.org/security/2001/dsa-054
Risk factor : High';

if (description) {
 script_id(14891);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "054");
 script_cve_id("CVE-2001-0559");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA054] DSA-054-1 cron");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-054-1 cron");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cron', release: '2.2', reference: '3.0pl1-57.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cron is vulnerable in Debian 2.2.\nUpgrade to cron_3.0pl1-57.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
