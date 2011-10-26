# This script was automatically generated from the dsa-1127
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in the Ethereal network
sniffer, which may lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:
    Ilja van Sprundel discovered that the FW-1 and MQ dissectors are
    vulnerable to format string attacks.
    Ilja van Sprundel discovered that the MOUNT dissector is vulnerable
    to denial of service through memory exhaustion.
    Ilja van Sprundel discovered off-by-one overflows in the NCP NMAS and
    NDPS dissectors.
    Ilja van Sprundel discovered a buffer overflow in the NFS dissector.
    Ilja van Sprundel discovered that the SSH dissector is vulnerable
    to denial of service through an infinite loop.
For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge6.
For the unstable distribution (sid) these problems have been fixed in
version 0.99.2-1 of wireshark, the sniffer formerly known as ethereal.
We recommend that you upgrade your ethereal packages.


Solution : http://www.debian.org/security/2006/dsa-1127
Risk factor : High';

if (description) {
 script_id(22669);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1127");
 script_cve_id("CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1127] DSA-1127-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1127-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '', reference: '0.99')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian .\nUpgrade to ethereal_0.99\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.10.10-2sarge6\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.1.\nUpgrade to ethereal-common_0.10.10-2sarge6\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.1.\nUpgrade to ethereal-dev_0.10.10-2sarge6\n');
}
if (deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.1.\nUpgrade to tethereal_0.10.10-2sarge6\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian sarge.\nUpgrade to ethereal_0.10.10-2sarge6\n');
}
if (w) { security_hole(port: 0, data: desc); }
