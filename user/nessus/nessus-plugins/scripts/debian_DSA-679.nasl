# This script was automatically generated from the dsa-679
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Sean Finney discovered several insecure temporary file uses in
toolchain-source, the GNU binutils and GCC source code and scripts.
These bugs can lead a local attacker with minimal knowledge to trick
the admin into overwriting arbitrary files via a symlink attack.  The
problems exist inside the Debian-specific tpkg-* scripts.
For the stable distribution (woody) these problems have been fixed in
version 3.0.4-1woody1.
For the unstable distribution (sid) these problems have been fixed in
version 3.4-5.
We recommend that you upgrade your toolchain-source package.


Solution : http://www.debian.org/security/2005/dsa-679
Risk factor : High';

if (description) {
 script_id(16383);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "679");
 script_cve_id("CVE-2005-0159");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA679] DSA-679-1 toolchain-source");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-679-1 toolchain-source");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'toolchain-source', release: '3.0', reference: '3.0.4-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package toolchain-source is vulnerable in Debian 3.0.\nUpgrade to toolchain-source_3.0.4-1woody1\n');
}
if (deb_check(prefix: 'toolchain-source', release: '3.1', reference: '3.4-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package toolchain-source is vulnerable in Debian 3.1.\nUpgrade to toolchain-source_3.4-5\n');
}
if (deb_check(prefix: 'toolchain-source', release: '3.0', reference: '3.0.4-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package toolchain-source is vulnerable in Debian woody.\nUpgrade to toolchain-source_3.0.4-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
