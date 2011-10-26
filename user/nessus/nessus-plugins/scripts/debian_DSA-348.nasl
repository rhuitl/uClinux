# This script was automatically generated from the dsa-348
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
traceroute-nanog, an enhanced version of the common traceroute
program, contains an integer overflow bug which could be exploited to
execute arbitrary code.  traceroute-nanog is setuid root, but drops
root privileges immediately after obtaining raw ICMP and raw IP
sockets.  Thus, exploitation of this bug provides only access to these
sockets, and not root privileges.
For the stable distribution (woody) this problem has been fixed in
version 6.1.1-1.3.
For the unstable distribution (sid) this problem will be fixed soon.
See Debian bug #200875.
We recommend that you update your traceroute-nanog package.


Solution : http://www.debian.org/security/2003/dsa-348
Risk factor : High';

if (description) {
 script_id(15185);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "348");
 script_cve_id("CVE-2003-0453");
 script_bugtraq_id(7994);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA348] DSA-348-1 traceroute-nanog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-348-1 traceroute-nanog");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'traceroute-nanog', release: '3.0', reference: '6.1.1-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package traceroute-nanog is vulnerable in Debian 3.0.\nUpgrade to traceroute-nanog_6.1.1-1.3\n');
}
if (deb_check(prefix: 'traceroute-nanog', release: '3.0', reference: '6.1.1-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package traceroute-nanog is vulnerable in Debian woody.\nUpgrade to traceroute-nanog_6.1.1-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
