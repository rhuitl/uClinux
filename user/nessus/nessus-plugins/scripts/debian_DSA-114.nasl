# This script was automatically generated from the dsa-114
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Thomas Springer found a vulnerability in GNUJSP, a Java servlet that
allows you to insert Java source code into HTML files.  The problem
can be used to bypass access restrictions in the web server.  An
attacker can view the contents of directories and download files
directly rather then receiving their HTML output.  This means that the
source code of scripts could also be revealed.
The problem was fixed by Stefan Gybas, who maintains the Debian
package of GNUJSP.  It is fixed in version 1.0.0-5 for the stable
release of Debian GNU/Linux.
The versions in testing and unstable are the same as the one in stable
so they are vulnerable, too.  You can install the fixed version this
advisory refers to on these systems to solve the problem as this
package is architecture independent.
We recommend that you upgrade your gnujsp package immediately.


Solution : http://www.debian.org/security/2002/dsa-114
Risk factor : High';

if (description) {
 script_id(14951);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "114");
 script_cve_id("CVE-2002-0300");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA114] DSA-114-1 gnujsp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-114-1 gnujsp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnujsp', release: '2.2', reference: '1.0.0-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnujsp is vulnerable in Debian 2.2.\nUpgrade to gnujsp_1.0.0-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
