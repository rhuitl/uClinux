# This script was automatically generated from the dsa-706
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered a
buffer overflow in axel, a light download accelerator.  When reading
remote input the program did not check if a part of the input can
overflow a buffer and maybe trigger the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 1.0a-1woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.0b-1.
We recommend that you upgrade your axel package.


Solution : http://www.debian.org/security/2005/dsa-706
Risk factor : High';

if (description) {
 script_id(18030);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "706");
 script_cve_id("CVE-2005-0390");
 script_bugtraq_id(13059);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA706] DSA-706-1 axel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-706-1 axel");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'axel', release: '3.0', reference: '1.0a-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package axel is vulnerable in Debian 3.0.\nUpgrade to axel_1.0a-1woody1\n');
}
if (deb_check(prefix: 'axel-kapt', release: '3.0', reference: '1.0a-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package axel-kapt is vulnerable in Debian 3.0.\nUpgrade to axel-kapt_1.0a-1woody1\n');
}
if (deb_check(prefix: 'axel', release: '3.1', reference: '1.0b-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package axel is vulnerable in Debian 3.1.\nUpgrade to axel_1.0b-1\n');
}
if (deb_check(prefix: 'axel', release: '3.0', reference: '1.0a-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package axel is vulnerable in Debian woody.\nUpgrade to axel_1.0a-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
