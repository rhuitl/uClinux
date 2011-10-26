# This script was automatically generated from the dsa-635
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Philip Hazel announced a buffer overflow in the host_aton function in
exim, the default mail-transport-agent in Debian, which can lead to the
execution of arbitrary code via an illegal IPv6 address.
For the stable distribution (woody) this problem has been fixed in
version 3.35-1woody4.
For the unstable distribution (sid) this problem has been fixed in
version 3.36-13 of exim and 4.34-10 of exim4.
We recommend that you upgrade your exim and exim4 packages.


Solution : http://www.debian.org/security/2005/dsa-635
Risk factor : High';

if (description) {
 script_id(16132);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "635");
 script_cve_id("CVE-2005-0021");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA635] DSA-635-1 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-635-1 exim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'exim', release: '3.0', reference: '3.35-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian 3.0.\nUpgrade to exim_3.35-1woody4\n');
}
if (deb_check(prefix: 'eximon', release: '3.0', reference: '3.35-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eximon is vulnerable in Debian 3.0.\nUpgrade to eximon_3.35-1woody4\n');
}
if (deb_check(prefix: 'exim', release: '3.1', reference: '3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian 3.1.\nUpgrade to exim_3\n');
}
if (deb_check(prefix: 'exim', release: '3.0', reference: '3.35-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian woody.\nUpgrade to exim_3.35-1woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
