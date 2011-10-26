# This script was automatically generated from the dsa-665
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered several bugs in ncpfs that provides utilities
to use resources from NetWare servers of which one also applies to the
stable Debian distribution.  Due to accessing a configuration file
without further checks with root permissions it is possible to read
arbitrary files.
For the stable distribution (woody) this problem has been fixed in
version 2.2.0.18-10woody2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your ncpfs package.


Solution : http://www.debian.org/security/2005/dsa-665
Risk factor : High';

if (description) {
 script_id(16311);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "665");
 script_cve_id("CVE-2005-0013");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA665] DSA-665-1 ncpfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-665-1 ncpfs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ipx', release: '3.0', reference: '2.2.0.18-10woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipx is vulnerable in Debian 3.0.\nUpgrade to ipx_2.2.0.18-10woody2\n');
}
if (deb_check(prefix: 'ncpfs', release: '3.0', reference: '2.2.0.18-10woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ncpfs is vulnerable in Debian 3.0.\nUpgrade to ncpfs_2.2.0.18-10woody2\n');
}
if (deb_check(prefix: 'ncpfs', release: '3.0', reference: '2.2.0.18-10woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ncpfs is vulnerable in Debian woody.\nUpgrade to ncpfs_2.2.0.18-10woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
