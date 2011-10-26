# This script was automatically generated from the dsa-162
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ethereal developers discovered a buffer overflow in the ISIS protocol
dissector.  It may be possible to make Ethereal crash or hang by
injecting a purposefully malformed packet onto the wire, or by
convincing someone to read a malformed packet trace file.  It may be
possible to make Ethereal run arbitrary code by exploiting the buffer
and pointer problems.
This problem has been fixed in version 0.9.4-1woody2 for the current
stable distribution (woody), in version 0.8.0-4potato.1 for
the old stable distribution (potato) and in version 0.9.6-1 for the
unstable distribution (sid).
We recommend that you upgrade your ethereal packages.


Solution : http://www.debian.org/security/2002/dsa-162
Risk factor : High';

if (description) {
 script_id(14999);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "162");
 script_cve_id("CVE-2002-0834");
 script_bugtraq_id(5573);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA162] DSA-162-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-162-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '2.2', reference: '0.8.0-4potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 2.2.\nUpgrade to ethereal_0.8.0-4potato.1\n');
}
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.0.\nUpgrade to ethereal_0.9.4-1woody2\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.0.\nUpgrade to ethereal-common_0.9.4-1woody2\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.0.\nUpgrade to ethereal-dev_0.9.4-1woody2\n');
}
if (deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.0.\nUpgrade to tethereal_0.9.4-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
