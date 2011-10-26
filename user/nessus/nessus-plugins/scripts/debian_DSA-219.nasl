# This script was automatically generated from the dsa-219
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Simon Kelly discovered a vulnerability in dhcpcd, an RFC2131 and
RFC1541 compliant DHCP client daemon, that runs with root privileges
on client machines.  A malicious administrator of the regular or an
untrusted DHCP server may execute any command with root privileges on
the DHCP client machine by sending the command enclosed in shell
metacharacters in one of the options provided by the DHCP server.
This problem has been fixed in version 1.3.17pl2-8.1 for the old
stable distribution (potato) and in version 1.3.22pl2-2 for the
testing (sarge) and unstable (sid) distributions.  The current stable
distribution (woody) does not contain a dhcpcd package.
We recommend that you upgrade your dhcpcd package (on the client
machine).


Solution : http://www.debian.org/security/2002/dsa-219
Risk factor : High';

if (description) {
 script_id(15056);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "219");
 script_cve_id("CVE-2002-1403");
 script_bugtraq_id(6200);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA219] DSA-219-1 dhcpcd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-219-1 dhcpcd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dhcpcd', release: '2.2', reference: '1.3.17pl2-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcpcd is vulnerable in Debian 2.2.\nUpgrade to dhcpcd_1.3.17pl2-8.1\n');
}
if (deb_check(prefix: 'dhcpcd', release: '3.0', reference: '1.3.22pl2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcpcd is vulnerable in Debian 3.0.\nUpgrade to dhcpcd_1.3.22pl2-2\n');
}
if (deb_check(prefix: 'dhcpcd', release: '2.2', reference: '1.3.17pl2-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcpcd is vulnerable in Debian potato.\nUpgrade to dhcpcd_1.3.17pl2-8.1\n');
}
if (deb_check(prefix: 'dhcpcd', release: '3.1', reference: '1.3.22pl2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcpcd is vulnerable in Debian sarge.\nUpgrade to dhcpcd_1.3.22pl2-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
