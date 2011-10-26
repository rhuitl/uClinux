# This script was automatically generated from the dsa-1142
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered missing boundary checks in freeciv, a clone
of the well known Civilisation game, which can be exploited by remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.1-1sarge2.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your freeciv package.


Solution : http://www.debian.org/security/2006/dsa-1142
Risk factor : High';

if (description) {
 script_id(22684);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1142");
 script_cve_id("CVE-2006-3913");
 script_bugtraq_id(19117);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1142] DSA-1142-1 freeciv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1142-1 freeciv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freeciv', release: '3.1', reference: '2.0.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv is vulnerable in Debian 3.1.\nUpgrade to freeciv_2.0.1-1sarge2\n');
}
if (deb_check(prefix: 'freeciv-client-gtk', release: '3.1', reference: '2.0.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-client-gtk is vulnerable in Debian 3.1.\nUpgrade to freeciv-client-gtk_2.0.1-1sarge2\n');
}
if (deb_check(prefix: 'freeciv-client-xaw3d', release: '3.1', reference: '2.0.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-client-xaw3d is vulnerable in Debian 3.1.\nUpgrade to freeciv-client-xaw3d_2.0.1-1sarge2\n');
}
if (deb_check(prefix: 'freeciv-data', release: '3.1', reference: '2.0.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-data is vulnerable in Debian 3.1.\nUpgrade to freeciv-data_2.0.1-1sarge2\n');
}
if (deb_check(prefix: 'freeciv-gtk', release: '3.1', reference: '2.0.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-gtk is vulnerable in Debian 3.1.\nUpgrade to freeciv-gtk_2.0.1-1sarge2\n');
}
if (deb_check(prefix: 'freeciv-server', release: '3.1', reference: '2.0.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-server is vulnerable in Debian 3.1.\nUpgrade to freeciv-server_2.0.1-1sarge2\n');
}
if (deb_check(prefix: 'freeciv-xaw3d', release: '3.1', reference: '2.0.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv-xaw3d is vulnerable in Debian 3.1.\nUpgrade to freeciv-xaw3d_2.0.1-1sarge2\n');
}
if (deb_check(prefix: 'freeciv', release: '3.1', reference: '2.0.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeciv is vulnerable in Debian sarge.\nUpgrade to freeciv_2.0.1-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
