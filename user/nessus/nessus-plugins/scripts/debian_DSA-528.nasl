# This script was automatically generated from the dsa-528
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several denial of service vulnerabilities were discovered in ethereal,
a network traffic analyzer.  These vulnerabilities are described in the
ethereal advisory "enpa-sa-00015".  Of these, only one (CVE-2004-0635)
affects the version of ethereal in Debian woody.  This vulnerability
could be exploited by a remote attacker to crash ethereal with an
invalid SNMP packet.
For the current stable distribution (woody), these problems have been
fixed in version 0.9.4-1woody8.
For the unstable distribution (sid), these problems have been fixed in
version 0.10.5-1.
We recommend that you update your ethereal package.


Solution : http://www.debian.org/security/2004/dsa-528
Risk factor : High';

if (description) {
 script_id(15365);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "528");
 script_cve_id("CVE-2004-0635");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA528] DSA-528-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-528-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.0.\nUpgrade to ethereal_0.9.4-1woody8\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.0.\nUpgrade to ethereal-common_0.9.4-1woody8\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.0.\nUpgrade to ethereal-dev_0.9.4-1woody8\n');
}
if (deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.0.\nUpgrade to tethereal_0.9.4-1woody8\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.10.5-1\n');
}
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian woody.\nUpgrade to ethereal_0.9.4-1woody8\n');
}
if (w) { security_hole(port: 0, data: desc); }
