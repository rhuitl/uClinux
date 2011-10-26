# This script was automatically generated from the dsa-472
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp and Jaguar discovered a number of buffer overflow
vulnerabilities in vfte, a version of the fte editor which runs on the
Linux console, found in the package fte-console.  This program is
setuid root in order to perform certain types of low-level operations
on the console.
Due to these bugs, setuid privilege has been removed from vfte, making
it only usable by root.  We recommend using the terminal version (in
the fte-terminal package) instead, which runs on any capable terminal
including the Linux console.
For the stable distribution (woody) these problems have been fixed in
version 0.49.13-15woody1.
For the unstable distribution (sid) these problems have been fixed in
version 0.50.0-1.1.
We recommend that you update your fte package.


Solution : http://www.debian.org/security/2004/dsa-472
Risk factor : High';

if (description) {
 script_id(15309);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "472");
 script_cve_id("CVE-2003-0648");
 script_bugtraq_id(10041);
 script_xref(name: "CERT", value: "354838");
 script_xref(name: "CERT", value: "900964");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA472] DSA-472-1 fte");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-472-1 fte");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fte', release: '3.0', reference: '0.49.13-15woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fte is vulnerable in Debian 3.0.\nUpgrade to fte_0.49.13-15woody1\n');
}
if (deb_check(prefix: 'fte-console', release: '3.0', reference: '0.49.13-15woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fte-console is vulnerable in Debian 3.0.\nUpgrade to fte-console_0.49.13-15woody1\n');
}
if (deb_check(prefix: 'fte-docs', release: '3.0', reference: '0.49.13-15woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fte-docs is vulnerable in Debian 3.0.\nUpgrade to fte-docs_0.49.13-15woody1\n');
}
if (deb_check(prefix: 'fte-terminal', release: '3.0', reference: '0.49.13-15woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fte-terminal is vulnerable in Debian 3.0.\nUpgrade to fte-terminal_0.49.13-15woody1\n');
}
if (deb_check(prefix: 'fte-xwindow', release: '3.0', reference: '0.49.13-15woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fte-xwindow is vulnerable in Debian 3.0.\nUpgrade to fte-xwindow_0.49.13-15woody1\n');
}
if (deb_check(prefix: 'fte', release: '3.1', reference: '0.50.0-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fte is vulnerable in Debian 3.1.\nUpgrade to fte_0.50.0-1.1\n');
}
if (deb_check(prefix: 'fte', release: '3.0', reference: '0.49.13-15woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fte is vulnerable in Debian woody.\nUpgrade to fte_0.49.13-15woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
