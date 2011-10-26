# This script was automatically generated from the dsa-121
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been found in the xtell
package, a simple messaging client and server.  In detail, these
problems contain several buffer overflows, a problem in connection
with symbolic links, unauthorized directory traversal when the path
contains "..".  These problems could lead into an attacker being able
to execute arbitrary code on the server machine.  The server runs with
nobody privileges by default, so this would be the account to be
exploited.
They have been corrected by backporting changes from a newer upstream
version by the Debian maintainer for xtell.  These problems are fixed
in version 1.91.1 in the stable distribution of Debian and in version
2.7 for the testing and unstable distribution of Debian.
We recommend that you upgrade your xtell packages immediately.


Solution : http://www.debian.org/security/2002/dsa-121
Risk factor : High';

if (description) {
 script_id(14958);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "121");
 script_cve_id("CVE-2002-0332", "CVE-2002-0333", "CVE-2002-0334");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA121] DSA-121-1 xtell");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-121-1 xtell");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xtell', release: '2.2', reference: '1.91.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xtell is vulnerable in Debian 2.2.\nUpgrade to xtell_1.91.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
