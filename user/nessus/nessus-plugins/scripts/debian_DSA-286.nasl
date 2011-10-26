# This script was automatically generated from the dsa-286
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Szabo discovered insecure creation of a temporary file in
ps2epsi, a script that is distributed as part of gs-common which
contains common files for different Ghostscript releases.  ps2epsi uses
a temporary file in the process of invoking ghostscript.  This file
was created in an insecure fashion, which could allow a local attacker
to overwrite files owned by a user who invokes ps2epsi.
For the stable distribution (woody) this problem has been fixed in
version 0.3.3.0woody1.
The old stable distribution (potato) is not affected by this problem.
For the unstable distribution (sid) this problem has been fixed in
version 0.3.3.1.
We recommend that you upgrade your gs-common package.


Solution : http://www.debian.org/security/2003/dsa-286
Risk factor : High';

if (description) {
 script_id(15123);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "286");
 script_cve_id("CVE-2003-0207");
 script_bugtraq_id(7337);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA286] DSA-286-1 gs-common");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-286-1 gs-common");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gs-common', release: '3.0', reference: '0.3.3.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gs-common is vulnerable in Debian 3.0.\nUpgrade to gs-common_0.3.3.0woody1\n');
}
if (deb_check(prefix: 'gs-common', release: '3.1', reference: '0.3.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gs-common is vulnerable in Debian 3.1.\nUpgrade to gs-common_0.3.3.1\n');
}
if (deb_check(prefix: 'gs-common', release: '3.0', reference: '0.3.3.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gs-common is vulnerable in Debian woody.\nUpgrade to gs-common_0.3.3.0woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
