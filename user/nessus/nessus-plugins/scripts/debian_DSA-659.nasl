# This script was automatically generated from the dsa-659
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two problems have been discovered in the libpam-radius-auth package,
the PAM RADIUS authentication module.  The Common Vulnerabilities and
Exposures Project identifies the following problems:
    The Debian package accidentally installed its configuration file
    /etc/pam_radius_auth.conf world-readable.  Since it may possibly
    contain secrets all local users are able to read them if the
    administrator hasn\'t adjusted file permissions.  This problem is
    Debian specific.
    Leon Juranic discovered an integer underflow in the mod_auth_radius
    module for Apache which is also present in libpam-radius-auth.
For the stable distribution (woody) these problems have been fixed in
version 1.3.14-1.3.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.16-3.
We recommend that you upgrade your libpam-radius-auth package.


Solution : http://www.debian.org/security/2005/dsa-659
Risk factor : High';

if (description) {
 script_id(16252);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "659");
 script_cve_id("CVE-2004-1340", "CVE-2005-0108");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA659] DSA-659-1 libpam-radius-auth");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-659-1 libpam-radius-auth");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpam-radius-auth', release: '3.0', reference: '1.3.14-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-radius-auth is vulnerable in Debian 3.0.\nUpgrade to libpam-radius-auth_1.3.14-1.3\n');
}
if (deb_check(prefix: 'libpam-radius-auth', release: '3.1', reference: '1.3.16-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-radius-auth is vulnerable in Debian 3.1.\nUpgrade to libpam-radius-auth_1.3.16-3\n');
}
if (deb_check(prefix: 'libpam-radius-auth', release: '3.0', reference: '1.3.14-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-radius-auth is vulnerable in Debian woody.\nUpgrade to libpam-radius-auth_1.3.14-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
