# This script was automatically generated from the dsa-1049
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Gerald Combs reported several vulnerabilities in ethereal, a popular
network traffic analyser.  The Common Vulnerabilities and Exposures
project identifies the following problems:
    The OID printing routine is susceptible to an off-by-one error.
     The UMA and BER dissectors could go into an infinite loop.
    The Network Instruments file code could overrun a buffer.
    The COPS dissector contains a potential buffer overflow.
    The telnet dissector contains a buffer overflow.
    Bugs in the SRVLOC and AIM dissector, and in the statistics
    counter could crash ethereal.
    Null pointer dereferences in the SMB PIPE dissector and when
    reading a malformed Sniffer capture could crash ethereal.
    Null pointer dereferences in the ASN.1, GSM SMS, RPC and
    ASN.1-based dissector and an invalid display filter could crash
    ethereal.
    The SNDCP dissector could cause an unintended abortion.
For the old stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody15.
For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge5.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your ethereal packages.


Solution : http://www.debian.org/security/2006/dsa-1049
Risk factor : High';

if (description) {
 script_id(22591);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1049");
 script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938");
 script_bugtraq_id(17682);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1049] DSA-1049-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1049-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.0.\nUpgrade to ethereal_0.9.4-1woody15\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.0.\nUpgrade to ethereal-common_0.9.4-1woody15\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.0.\nUpgrade to ethereal-dev_0.9.4-1woody15\n');
}
if (deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.0.\nUpgrade to tethereal_0.9.4-1woody15\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.10.10-2sarge5\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.1.\nUpgrade to ethereal-common_0.10.10-2sarge5\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.1.\nUpgrade to ethereal-dev_0.10.10-2sarge5\n');
}
if (deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.1.\nUpgrade to tethereal_0.10.10-2sarge5\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian sarge.\nUpgrade to ethereal_0.10.10-2sarge5\n');
}
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian woody.\nUpgrade to ethereal_0.9.4-1woody15\n');
}
if (w) { security_hole(port: 0, data: desc); }
