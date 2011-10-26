# This script was automatically generated from the dsa-663
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several buffer overflows have been discovered in prozilla, a
multi-threaded download accelerator which could be exploited by a
remote attacker to execute arbitrary code on the victim\'s machine.  An
exploit for prozilla is already in the wild.
For the stable distribution (woody) these problems have been fixed in
version 1.3.6-3woody1.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.7.3-1.
We recommend that you upgrade your prozilla package.


Solution : http://www.debian.org/security/2005/dsa-663
Risk factor : High';

if (description) {
 script_id(16284);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "663");
 script_cve_id("CVE-2004-1120");
 script_bugtraq_id(11734);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA663] DSA-663-1 prozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-663-1 prozilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'prozilla', release: '3.0', reference: '1.3.6-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package prozilla is vulnerable in Debian 3.0.\nUpgrade to prozilla_1.3.6-3woody1\n');
}
if (deb_check(prefix: 'prozilla', release: '3.1', reference: '1.3.7.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package prozilla is vulnerable in Debian 3.1.\nUpgrade to prozilla_1.3.7.3-1\n');
}
if (deb_check(prefix: 'prozilla', release: '3.0', reference: '1.3.6-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package prozilla is vulnerable in Debian woody.\nUpgrade to prozilla_1.3.6-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
