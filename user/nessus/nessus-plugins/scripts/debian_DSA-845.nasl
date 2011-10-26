# This script was automatically generated from the dsa-845
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Christoph Martin noticed that upon configuration mason, which
interactively creates a Linux packet filtering firewall, does not
install the init script to actually load the firewall during system
boot.  This will leave the machine without a firewall after a reboot.
For the old stable distribution (woody) this problem has been fixed in
version 0.13.0.92-2woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.0-2.2.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.0-3.
We recommend that you upgrade your mason package.


Solution : http://www.debian.org/security/2005/dsa-845
Risk factor : High';

if (description) {
 script_id(19953);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "845");
 script_cve_id("CVE-2005-3118");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA845] DSA-845-1 mason");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-845-1 mason");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mason', release: '', reference: '1.0.0-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mason is vulnerable in Debian .\nUpgrade to mason_1.0.0-3\n');
}
if (deb_check(prefix: 'mason', release: '3.0', reference: '0.13.0.92-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mason is vulnerable in Debian 3.0.\nUpgrade to mason_0.13.0.92-2woody1\n');
}
if (deb_check(prefix: 'mason', release: '3.1', reference: '1.0.0-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mason is vulnerable in Debian 3.1.\nUpgrade to mason_1.0.0-2.2\n');
}
if (deb_check(prefix: 'mason', release: '3.1', reference: '1.0.0-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mason is vulnerable in Debian sarge.\nUpgrade to mason_1.0.0-2.2\n');
}
if (deb_check(prefix: 'mason', release: '3.0', reference: '0.13.0.92-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mason is vulnerable in Debian woody.\nUpgrade to mason_0.13.0.92-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
