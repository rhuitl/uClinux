# This script was automatically generated from the dsa-333
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
acm, a multi-player aerial combat simulation, uses a network protocol
based on the same RPC implementation used in many C libraries.  This
implementation was found to contain an integer overflow vulnerability
which could be exploited to execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 5.0-3.woody.1.
For the unstable distribution (sid) this problem has been fixed in
version 5.0-10.
We recommend that you update your acm package.


Solution : http://www.debian.org/security/2003/dsa-333
Risk factor : High';

if (description) {
 script_id(15170);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "333");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA333] DSA-333-1 acm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-333-1 acm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'acm', release: '3.0', reference: '5.0-3.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acm is vulnerable in Debian 3.0.\nUpgrade to acm_5.0-3.woody.1\n');
}
if (deb_check(prefix: 'acm', release: '3.1', reference: '5.0-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acm is vulnerable in Debian 3.1.\nUpgrade to acm_5.0-10\n');
}
if (deb_check(prefix: 'acm', release: '3.0', reference: '5.0-3.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acm is vulnerable in Debian woody.\nUpgrade to acm_5.0-3.woody.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
