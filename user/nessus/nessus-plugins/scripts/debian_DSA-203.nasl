# This script was automatically generated from the dsa-203
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Robert Luberda found a security problem in smb2www, a Windows Network
client that is accessible through a web browser.  This could lead a
remote attacker to execute arbitrary programs under the user id
www-data on the host where smb2www is running.
This problem has been fixed in version 980804-16.1 for the current
stable distribution (woody), in version 980804-8.1 of the old stable
distribution (potato) and in version 980804-17 for the unstable
distribution (sid).
We recommend that you upgrade your smb2www package immediately.


Solution : http://www.debian.org/security/2002/dsa-203
Risk factor : High';

if (description) {
 script_id(15040);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "203");
 script_cve_id("CVE-2002-1342");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA203] DSA-203-1 smb2www");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-203-1 smb2www");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'smb2www', release: '2.2', reference: '980804-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smb2www is vulnerable in Debian 2.2.\nUpgrade to smb2www_980804-8.1\n');
}
if (deb_check(prefix: 'smb2www', release: '3.0', reference: '980804-16.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smb2www is vulnerable in Debian 3.0.\nUpgrade to smb2www_980804-16.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
