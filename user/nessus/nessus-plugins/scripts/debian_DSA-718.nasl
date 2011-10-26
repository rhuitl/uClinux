# This script was automatically generated from the dsa-718
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
[&nbsp;This version lists the correct packages in the packages
section.&nbsp;]
A buffer overflow has been detected in the IAPP dissector of Ethereal,
a commonly used network traffic analyser.  A remote attacker may be
able to overflow a buffer using a specially crafted packet.  More
problems have been discovered which don\'t apply to the version in
woody but are fixed in sid as well.
For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody12.
For the unstable distribution (sid) these problems have been fixed in
version 0.10.10-1.
We recommend that you upgrade your ethereal packages.


Solution : http://www.debian.org/security/2005/dsa-718
Risk factor : High';

if (description) {
 script_id(18157);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0008");
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "718");
 script_cve_id("CVE-2005-0739");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA718] DSA-718-2 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-718-2 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.0.\nUpgrade to ethereal_0.9.4-1woody12\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.10.10-1\n');
}
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian woody.\nUpgrade to ethereal_0.9.4-1woody12\n');
}
if (w) { security_hole(port: 0, data: desc); }
