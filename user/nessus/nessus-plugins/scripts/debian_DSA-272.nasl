# This script was automatically generated from the dsa-272
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
eEye Digital Security discovered an integer overflow in the
xdrmem_getbytes() function of glibc, that is also present in dietlibc,
a small libc useful especially for small and embedded systems.  This
function is part of the XDR encoder/decoder derived from Sun\'s RPC
implementation.  Depending upon the application, this vulnerability
can cause buffer overflows and could possibly be exploited to execute
arbitrary code.
For the stable distribution (woody) this problem has been
fixed in version 0.12-2.5.
The old stable distribution (potato) does not contain dietlibc
packages.
For the unstable distribution (sid) this problem has been
fixed in version 0.22-2.
We recommend that you upgrade your dietlibc packages.


Solution : http://www.debian.org/security/2003/dsa-272
Risk factor : High';

if (description) {
 script_id(15109);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0007");
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "272");
 script_cve_id("CVE-2003-0028");
 script_bugtraq_id(7123);
 script_xref(name: "CERT", value: "516825");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA272] DSA-272-1 dietlibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-272-1 dietlibc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dietlibc-dev', release: '3.0', reference: '0.12-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dietlibc-dev is vulnerable in Debian 3.0.\nUpgrade to dietlibc-dev_0.12-2.5\n');
}
if (deb_check(prefix: 'dietlibc-doc', release: '3.0', reference: '0.12-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dietlibc-doc is vulnerable in Debian 3.0.\nUpgrade to dietlibc-doc_0.12-2.5\n');
}
if (deb_check(prefix: 'dietlibc', release: '3.1', reference: '0.22-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dietlibc is vulnerable in Debian 3.1.\nUpgrade to dietlibc_0.22-2\n');
}
if (deb_check(prefix: 'dietlibc', release: '3.0', reference: '0.12-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dietlibc is vulnerable in Debian woody.\nUpgrade to dietlibc_0.12-2.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
