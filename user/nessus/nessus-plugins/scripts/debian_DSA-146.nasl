# This script was automatically generated from the dsa-146
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An integer overflow bug has been discovered in the RPC library used by
dietlibc, a libc optimized for small size, which is derived from the
SunRPC library.  This bug could be exploited to gain unauthorized root
access to software linking to this code.  The packages below also fix
integer overflows in the calloc, fread and fwrite code.  They are also
more strict regarding hostile DNS packets that could lead to a
vulnerability otherwise.
These problems have been fixed in version 0.12-2.4 for the current
stable distribution (woody) and in version 0.20-0cvs20020808 for the
unstable distribution (sid).  Debian 2.2 (potato) is not affected
since it doesn\'t contain dietlibc packages.
We recommend that you upgrade your dietlibc packages immediately.


Solution : http://www.debian.org/security/2002/dsa-146
Risk factor : High';

if (description) {
 script_id(14983);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "146");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);
 script_xref(name: "CERT", value: "192995");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA146] DSA-146-2 dietlibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-146-2 dietlibc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dietlibc-dev', release: '3.0', reference: '0.12-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dietlibc-dev is vulnerable in Debian 3.0.\nUpgrade to dietlibc-dev_0.12-2.4\n');
}
if (deb_check(prefix: 'dietlibc-doc', release: '3.0', reference: '0.12-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dietlibc-doc is vulnerable in Debian 3.0.\nUpgrade to dietlibc-doc_0.12-2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
