# This script was automatically generated from the dsa-150
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in Interchange, an e-commerce and
general HTTP database display system, which can lead to an attacker
being able to read any file to which the user of the Interchange
daemon has sufficient permissions, when Interchange runs in "INET
mode" (internet domain socket).  This is not the default setting in
Debian packages, but configurable with Debconf and via configuration
file.  We also believe that this bug cannot exploited on a regular
Debian system.
This problem has been fixed by the package maintainer in version
4.8.3.20020306-1.woody.1 for the current stable distribution (woody)
and in version 4.8.6-1 for the unstable distribution (sid).  The old
stable distribution (potato) is not affected, since it doesn\'t ship
the Interchange system.
We recommend that you upgrade your interchange packages.


Solution : http://www.debian.org/security/2002/dsa-150
Risk factor : High';

if (description) {
 script_id(14987);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "150");
 script_cve_id("CVE-2002-0874");
 script_bugtraq_id(5453);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA150] DSA-150-1 interchange");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-150-1 interchange");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package interchange is vulnerable in Debian 3.0.\nUpgrade to interchange_4.8.3.20020306-1.woody.1\n');
}
if (deb_check(prefix: 'interchange-cat-foundation', release: '3.0', reference: '4.8.3.20020306-1.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package interchange-cat-foundation is vulnerable in Debian 3.0.\nUpgrade to interchange-cat-foundation_4.8.3.20020306-1.woody.1\n');
}
if (deb_check(prefix: 'interchange-ui', release: '3.0', reference: '4.8.3.20020306-1.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package interchange-ui is vulnerable in Debian 3.0.\nUpgrade to interchange-ui_4.8.3.20020306-1.woody.1\n');
}
if (deb_check(prefix: 'libapache-mod-interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-interchange is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-interchange_4.8.3.20020306-1.woody.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
