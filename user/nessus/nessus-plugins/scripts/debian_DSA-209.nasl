# This script was automatically generated from the dsa-209
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two problems have been found in the wget package as distributed in
Debian GNU/Linux:
Both problems have been fixed in version 1.5.3-3.1 for Debian GNU/Linux
2.2/potato and version 1.8.1-6.1 for Debian GNU/Linux 3.0/woody.


Solution : http://www.debian.org/security/2002/dsa-209
Risk factor : High';

if (description) {
 script_id(15046);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "209");
 script_cve_id("CVE-2002-1344", "CVE-2002-1565");
 script_bugtraq_id(6352);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA209] DSA-209-1 wget");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-209-1 wget");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wget', release: '2.2', reference: '1.5.3-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wget is vulnerable in Debian 2.2.\nUpgrade to wget_1.5.3-3.1\n');
}
if (deb_check(prefix: 'wget', release: '3.0', reference: '1.8.1-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wget is vulnerable in Debian 3.0.\nUpgrade to wget_1.8.1-6.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
