# This script was automatically generated from the dsa-560
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered several stack and integer overflows in the
libXpm library which is included in LessTif.
For the stable distribution (woody) this problem has been fixed in
version 0.93.18-5.
For the unstable distribution (sid) this problem has been fixed in
version 0.93.94-10.
We recommend that you upgrade your lesstif packages.


Solution : http://www.debian.org/security/2004/dsa-560
Risk factor : High';

if (description) {
 script_id(15658);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "560");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688");
 script_xref(name: "CERT", value: "537878");
 script_xref(name: "CERT", value: "882750");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA560] DSA-560-1 lesstif1-1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-560-1 lesstif1-1");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lesstif-bin', release: '3.0', reference: '0.93.18-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lesstif-bin is vulnerable in Debian 3.0.\nUpgrade to lesstif-bin_0.93.18-5\n');
}
if (deb_check(prefix: 'lesstif-dbg', release: '3.0', reference: '0.93.18-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lesstif-dbg is vulnerable in Debian 3.0.\nUpgrade to lesstif-dbg_0.93.18-5\n');
}
if (deb_check(prefix: 'lesstif-dev', release: '3.0', reference: '0.93.18-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lesstif-dev is vulnerable in Debian 3.0.\nUpgrade to lesstif-dev_0.93.18-5\n');
}
if (deb_check(prefix: 'lesstif-doc', release: '3.0', reference: '0.93.18-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lesstif-doc is vulnerable in Debian 3.0.\nUpgrade to lesstif-doc_0.93.18-5\n');
}
if (deb_check(prefix: 'lesstif1', release: '3.0', reference: '0.93.18-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lesstif1 is vulnerable in Debian 3.0.\nUpgrade to lesstif1_0.93.18-5\n');
}
if (deb_check(prefix: 'lesstif1-1', release: '3.1', reference: '0.93.94-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lesstif1-1 is vulnerable in Debian 3.1.\nUpgrade to lesstif1-1_0.93.94-10\n');
}
if (deb_check(prefix: 'lesstif1-1', release: '3.0', reference: '0.93.18-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lesstif1-1 is vulnerable in Debian woody.\nUpgrade to lesstif1-1_0.93.18-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
