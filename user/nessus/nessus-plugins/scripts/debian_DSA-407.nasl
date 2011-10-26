# This script was automatically generated from the dsa-407
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities were discovered upstream in ethereal, a
network traffic analyzer.  The Common Vulnerabilities and Exposures
project identifies the following problems:
A buffer overflow allows remote attackers to cause a denial of
   service and possibly execute arbitrary code via a malformed GTP
   MSISDN string.
Via certain malformed ISAKMP or MEGACO packets remote attackers are
   able to cause a denial of service (crash).
A heap-based buffer overflow allows remote attackers to cause a
   denial of service (crash) and possibly execute arbitrary code via
   the SOCKS dissector.
The SMB dissector allows remote attackers to cause a denial of
   service via a malformed SMB packet that triggers a segmentation
   fault during processing of selected packets.
The Q.931 dissector allows remote attackers to cause a denial of
   service (crash) via a malformed Q.931, which triggers a null
   dereference.
For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody6.
For the unstable distribution (sid) this problem has been fixed in
version 0.10.0-1.
We recommend that you upgrade your ethereal and tethereal packages.


Solution : http://www.debian.org/security/2004/dsa-407
Risk factor : High';

if (description) {
 script_id(15244);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "407");
 script_cve_id("CVE-2003-0925", "CVE-2003-0926", "CVE-2003-0927", "CVE-2003-1012", "CVE-2003-1013");
 script_bugtraq_id(9248, 9249);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA407] DSA-407-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-407-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.0.\nUpgrade to ethereal_0.9.4-1woody6\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.0.\nUpgrade to ethereal-common_0.9.4-1woody6\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.0.\nUpgrade to ethereal-dev_0.9.4-1woody6\n');
}
if (deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.0.\nUpgrade to tethereal_0.9.4-1woody6\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.0-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.10.0-1\n');
}
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian woody.\nUpgrade to ethereal_0.9.4-1woody6\n');
}
if (w) { security_hole(port: 0, data: desc); }
