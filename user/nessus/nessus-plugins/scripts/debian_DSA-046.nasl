# This script was automatically generated from the dsa-046
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Colin Phipps discovered that the exuberant-ctags packages as distributed
with Debian GNU/Linux 2.2 creates temporary files insecurely. This has
been fixed in version 1:3.2.4-0.1 of the Debian package, and upstream
version 3.5.

Note: DSA-046-1 included an incorrectly compiled sparc package, which
the second edition fixed.



Solution : http://www.debian.org/security/2001/dsa-046
Risk factor : High';

if (description) {
 script_id(14883);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "046");
 script_cve_id("CVE-2001-0430");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA046] DSA-046-2 exuberant-ctags");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-046-2 exuberant-ctags");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'exuberant-ctags', release: '2.2', reference: '3.2.4-0.1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exuberant-ctags is vulnerable in Debian 2.2.\nUpgrade to exuberant-ctags_3.2.4-0.1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
