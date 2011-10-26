# This script was automatically generated from the dsa-990
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A denial of service condition has been discovered in bluez-hcidump, a
utility that analyses Bluetooth HCI packets, which can be triggered
remotely.
The old stable distribution (woody) does not contain bluez-hcidump packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.17-1sarge1
For the unstable distribution (sid) this problem has been fixed in
version 1.30-1.
We recommend that you upgrade your bluez-hcidump package.


Solution : http://www.debian.org/security/2006/dsa-990
Risk factor : High';

if (description) {
 script_id(22856);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "990");
 script_cve_id("CVE-2006-0670");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA990] DSA-990-1 bluez-hcidump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-990-1 bluez-hcidump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bluez-hcidump', release: '', reference: '1.30-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-hcidump is vulnerable in Debian .\nUpgrade to bluez-hcidump_1.30-1\n');
}
if (deb_check(prefix: 'bluez-hcidump', release: '3.1', reference: '1.17-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-hcidump is vulnerable in Debian 3.1.\nUpgrade to bluez-hcidump_1.17-1sarge1\n');
}
if (deb_check(prefix: 'bluez-hcidump', release: '3.1', reference: '1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-hcidump is vulnerable in Debian sarge.\nUpgrade to bluez-hcidump_1\n');
}
if (w) { security_hole(port: 0, data: desc); }
