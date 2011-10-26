# This script was automatically generated from the dsa-1171
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in the Ethereal network
scanner, which may lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:
    It was discovered that the Q.2391 dissector is vulnerable to denial
    of service caused by memory exhaustion.
    It was discovered that the FC-FCS, RSVP and ISIS-LSP dissectors are
    vulnerable to denial of service caused by memory exhaustion.
    It was discovered that the IrDA and SMB dissectors are vulnerable to
    denial of service caused by memory corruption.
    It was discovered that the SLIMP3 and AgentX dissectors are vulnerable
    to code injection caused by buffer overflows.
    It was discovered that the BER dissector is vulnerable to denial of
    service caused by an infinite loop.
    It was discovered that the NCP and RTnet dissectors are vulnerable to
    denial of service caused by a null pointer dereference.
    It was discovered that the X11 dissector is vulnerable to denial of service
    caused by a division through zero.
This update also fixes a 64 bit-specific regression in the ASN.1 decoder, which
was introduced in a previous DSA.
For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge8.
For the unstable distribution (sid) these problems have been fixed in
version 0.99.2-5.1 of wireshark, the network sniffer formerly known as
ethereal.
We recommend that you upgrade your ethereal packages.


Solution : http://www.debian.org/security/2006/dsa-1171
Risk factor : High';

if (description) {
 script_id(22713);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1171");
 script_cve_id("CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3246", "CVE-2005-3248", "CVE-2006-4333");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1171] DSA-1171-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1171-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '', reference: '0.99.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian .\nUpgrade to ethereal_0.99.2-5\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.10.10-2sarge8\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.1.\nUpgrade to ethereal-common_0.10.10-2sarge8\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.1.\nUpgrade to ethereal-dev_0.10.10-2sarge8\n');
}
if (deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.1.\nUpgrade to tethereal_0.10.10-2sarge8\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian sarge.\nUpgrade to ethereal_0.10.10-2sarge8\n');
}
if (w) { security_hole(port: 0, data: desc); }
