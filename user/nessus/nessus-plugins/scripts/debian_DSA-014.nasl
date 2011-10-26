# This script was automatically generated from the dsa-014
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'It was reported recently that splitvt is vulnerable to
numerous buffer overflow attack and a format string attack. An attacker was
able to gain access to the root user id.

We recommend you upgrade your splitvt package immediately.


Solution : http://www.debian.org/security/2001/dsa-014
Risk factor : High';

if (description) {
 script_id(14851);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "014");
 script_cve_id("CVE-2001-0112", "CVE-2001-0111");
 script_bugtraq_id(2210);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA014] DSA-014-2 splitvt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-014-2 splitvt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'splitvt', release: '2.2', reference: '1.6.5-0potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package splitvt is vulnerable in Debian 2.2.\nUpgrade to splitvt_1.6.5-0potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
