# This script was automatically generated from the dsa-1020
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Moore discovered that flex, a scanner generator, generates code,
which allocates insufficient memory, if the grammar contains REJECT
statements or trailing context rules. This may lead to a buffer overflow
and the execution of arbitrary code.
If you use code, which is derived from a vulnerable lex grammar in
an untrusted environment you need to regenerate your scanner with the
fixed version of flex.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.5.31-31sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.5.33-1.
We recommend that you upgrade your flex package.


Solution : http://www.debian.org/security/2006/dsa-1020
Risk factor : High';

if (description) {
 script_id(22562);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1020");
 script_cve_id("CVE-2006-0459");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1020] DSA-1020-1 flex");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1020-1 flex");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'flex', release: '', reference: '2.5.33-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package flex is vulnerable in Debian .\nUpgrade to flex_2.5.33-1\n');
}
if (deb_check(prefix: 'flex', release: '3.1', reference: '2.5.31-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package flex is vulnerable in Debian 3.1.\nUpgrade to flex_2.5.31-31sarge1\n');
}
if (deb_check(prefix: 'flex-doc', release: '3.1', reference: '2.5.31-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package flex-doc is vulnerable in Debian 3.1.\nUpgrade to flex-doc_2.5.31-31sarge1\n');
}
if (deb_check(prefix: 'flex', release: '3.1', reference: '2.5.31-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package flex is vulnerable in Debian sarge.\nUpgrade to flex_2.5.31-31sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
