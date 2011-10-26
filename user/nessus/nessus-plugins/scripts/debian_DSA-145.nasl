# This script was automatically generated from the dsa-145
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The authors of tinyproxy, a lightweight HTTP proxy, discovered a bug
in the handling of some invalid proxy requests.  Under some
circumstances, an invalid request may result in allocated memory
being freed twice.  This can potentially result in the execution of
arbitrary code.
This problem has been fixed in version 1.4.3-2woody2 for the current
stable distribution (woody) and in version 1.4.3-3 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected by this problem.
We recommend that you upgrade your tinyproxy package immediately.


Solution : http://www.debian.org/security/2002/dsa-145
Risk factor : High';

if (description) {
 script_id(14982);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "145");
 script_cve_id("CVE-2002-0847");
 script_bugtraq_id(4731);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA145] DSA-145-1 tinyproxy");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-145-1 tinyproxy");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tinyproxy', release: '3.0', reference: '1.4.3-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tinyproxy is vulnerable in Debian 3.0.\nUpgrade to tinyproxy_1.4.3-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
