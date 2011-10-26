# This script was automatically generated from the dsa-637
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Philip Hazel announced a buffer overflow in the host_aton function in
exim-tls, the SSL-enabled version of the default mail-transport-agent
in Debian, which can lead to the execution of arbitrary code via an
illegal IPv6 address.
For the stable distribution (woody) this problem has been fixed in
version 3.35-3woody3.
In the unstable distribution (sid) this package does not exist
anymore.
We recommend that you upgrade your exim-tls package.


Solution : http://www.debian.org/security/2005/dsa-637
Risk factor : High';

if (description) {
 script_id(16155);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "637");
 script_cve_id("CVE-2005-0021");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA637] DSA-637-1 exim-tls");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-637-1 exim-tls");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'exim-tls', release: '3.0', reference: '3.35-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim-tls is vulnerable in Debian 3.0.\nUpgrade to exim-tls_3.35-3woody3\n');
}
if (deb_check(prefix: 'exim-tls', release: '3.0', reference: '3.35-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim-tls is vulnerable in Debian woody.\nUpgrade to exim-tls_3.35-3woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
