# This script was automatically generated from the dsa-749
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in the ettercap package which could allow
a remote attacker to execute arbitrary code on the system running
ettercap.
The old stable distribution (woody) did not include ettercap.
For the stable distribution (sarge), this problem has been fixed in
version 0.7.1-1sarge1.
For the unstable distribution (sid), this problem has been fixed in
version 0.7.3-1.
We recommend that you upgrade your ettercap package.


Solution : http://www.debian.org/security/2005/dsa-749
Risk factor : High';

if (description) {
 script_id(18664);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "749");
 script_cve_id("CVE-2005-1796");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA749] DSA-749-1 ettercap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-749-1 ettercap");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ettercap', release: '', reference: '0.7.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ettercap is vulnerable in Debian .\nUpgrade to ettercap_0.7.3-1\n');
}
if (deb_check(prefix: 'ettercap', release: '3.1', reference: '0.7.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ettercap is vulnerable in Debian 3.1.\nUpgrade to ettercap_0.7.1-1sarge1\n');
}
if (deb_check(prefix: 'ettercap-common', release: '3.1', reference: '0.7.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ettercap-common is vulnerable in Debian 3.1.\nUpgrade to ettercap-common_0.7.1-1sarge1\n');
}
if (deb_check(prefix: 'ettercap-gtk', release: '3.1', reference: '0.7.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ettercap-gtk is vulnerable in Debian 3.1.\nUpgrade to ettercap-gtk_0.7.1-1sarge1\n');
}
if (deb_check(prefix: 'ettercap', release: '3.1', reference: '0.7.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ettercap is vulnerable in Debian sarge.\nUpgrade to ettercap_0.7.1-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
