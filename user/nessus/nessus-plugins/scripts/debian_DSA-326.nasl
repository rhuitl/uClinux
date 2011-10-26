# This script was automatically generated from the dsa-326
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Orville Write, a replacement for the standard write(1) command,
contains a number of buffer overflows.  These could be exploited to
gain either gid tty or root privileges, depending on the configuration
selected when the package is installed.
For the stable distribution (woody) this problem has been fixed in
version 2.53-4woody1.
The old stable distribution (potato) does not contain an orville-write
package.
For the unstable distribution (sid) this problem will be fixed soon.
See Debian bug report #170747.
We recommend that you update your orville-write package.


Solution : http://www.debian.org/security/2003/dsa-326
Risk factor : High';

if (description) {
 script_id(15163);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "326");
 script_cve_id("CVE-2003-0441");
 script_bugtraq_id(7988);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA326] DSA-326-1 orville-write");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-326-1 orville-write");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'orville-write', release: '3.0', reference: '2.53-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package orville-write is vulnerable in Debian 3.0.\nUpgrade to orville-write_2.53-4woody1\n');
}
if (deb_check(prefix: 'orville-write', release: '3.0', reference: '2.53-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package orville-write is vulnerable in Debian woody.\nUpgrade to orville-write_2.53-4woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
