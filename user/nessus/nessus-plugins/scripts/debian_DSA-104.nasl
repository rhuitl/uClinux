# This script was automatically generated from the dsa-104
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Larry McVoy found a bug in the packet handling code for the CIPE
VPN package: it did not check if a received packet was too short 
and could crash.
This has been fixed in version 1.3.0-3, and we recommend that you
upgrade your CIPE packages immediately.
Please note that the package only contains the required kernel patch,
you will have to manually build the kernel modules for your kernel with the
updated source from the cipe-source package.


Solution : http://www.debian.org/security/2002/dsa-104
Risk factor : High';

if (description) {
 script_id(14941);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "104");
 script_cve_id("CVE-2002-0047");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA104] DSA-104-1 cipe");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-104-1 cipe");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cipe-common', release: '2.2', reference: '1.3.0-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cipe-common is vulnerable in Debian 2.2.\nUpgrade to cipe-common_1.3.0-3\n');
}
if (deb_check(prefix: 'cipe-source', release: '2.2', reference: '1.3.0-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cipe-source is vulnerable in Debian 2.2.\nUpgrade to cipe-source_1.3.0-3\n');
}
if (w) { security_hole(port: 0, data: desc); }
