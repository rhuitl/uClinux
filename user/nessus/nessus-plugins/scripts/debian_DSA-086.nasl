# This script was automatically generated from the dsa-086
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
We have received reports that the "SSH CRC-32 compensation attack
detector vulnerability" is being actively exploited. This is the same
integer type error previously corrected for OpenSSH in DSA-027-1.
OpenSSH (the Debian ssh package) was fixed at that time, but
ssh-nonfree and ssh-socks were not.
Though packages in the non-free section of the archive are not
officially supported by the Debian project, we are taking the unusual
step of releasing updated ssh-nonfree/ssh-socks packages for those
users who have not yet migrated to OpenSSH. However, we do recommend
that our users migrate to the regularly supported, DFSG-free "ssh"
package as soon as possible. ssh 1.2.3-9.3 is the OpenSSH package
available in Debian 2.2r4.
The fixed ssh-nonfree/ssh-socks packages are available in version
1.2.27-6.2 for use with Debian 2.2 (potato) and version 1.2.27-8 for
use with the Debian unstable/testing distribution. Note that the new
ssh-nonfree/ssh-socks packages remove the setuid bit from the ssh
binary, disabling rhosts-rsa authentication. If you need this
functionality, run
chmod u+s /usr/bin/ssh1
after installing the new package.


Solution : http://www.debian.org/security/2001/dsa-086
Risk factor : High';

if (description) {
 script_id(14923);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "086");
 script_cve_id("CVE-2001-0361");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA086] DSA-086-1 ssh-nonfree");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-086-1 ssh-nonfree");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ssh-askpass-nonfree', release: '2.2', reference: '1.2.27-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-askpass-nonfree is vulnerable in Debian 2.2.\nUpgrade to ssh-askpass-nonfree_1.2.27-6.2\n');
}
if (deb_check(prefix: 'ssh-nonfree', release: '2.2', reference: '1.2.27-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-nonfree is vulnerable in Debian 2.2.\nUpgrade to ssh-nonfree_1.2.27-6.2\n');
}
if (deb_check(prefix: 'ssh-socks', release: '2.2', reference: '1.2.27-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-socks is vulnerable in Debian 2.2.\nUpgrade to ssh-socks_1.2.27-6.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
