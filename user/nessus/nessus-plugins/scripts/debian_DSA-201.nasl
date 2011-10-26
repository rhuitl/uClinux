# This script was automatically generated from the dsa-201
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Bindview discovered a problem in several IPSEC implementations that do
not properly handle certain very short packets.  IPSEC is a set of
security extensions to IP which provide authentication and encryption.
Free/SWan in Debian is affected by this and is said to cause a kernel
panic.
This problem has been fixed in version 1.96-1.4 for the current stable
distribution (woody) and in version 1.99-1 for the unstable
distribution (sid).  The old stable distribution (potato) does not
contain Free/SWan packages.
We recommend that you upgrade your freeswan package.


Solution : http://www.debian.org/security/2002/dsa-201
Risk factor : High';

if (description) {
 script_id(15038);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "201");
 script_cve_id("CVE-2002-0666");
 script_xref(name: "CERT", value: "459371");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA201] DSA-201-1 freeswan");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-201-1 freeswan");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freeswan', release: '3.0', reference: '1.96-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeswan is vulnerable in Debian 3.0.\nUpgrade to freeswan_1.96-1.4\n');
}
if (deb_check(prefix: 'kernel-patch-freeswan', release: '3.0', reference: '1.96-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-freeswan is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-freeswan_1.96-1.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
