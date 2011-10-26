# This script was automatically generated from the dsa-477
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Shaun Colley discovered a problem in xine-ui, the xine video player
user interface.  A script contained in the package to possibly remedy
a problem or report a bug does not create temporary files in a secure
fashion.  This could allow a local attacker to overwrite files with
the privileges of the user invoking xine.
This update also removes the bug reporting facility since bug reports
can\'t be processed upstream anymore.
For the stable distribution (woody) this problem has been fixed in
version 0.9.8-5.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your xine-ui package.


Solution : http://www.debian.org/security/2004/dsa-477
Risk factor : High';

if (description) {
 script_id(15314);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "477");
 script_cve_id("CVE-2004-0372");
 script_bugtraq_id(9939, 9939);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA477] DSA-477-1 xine-ui");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-477-1 xine-ui");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xine-ui', release: '3.0', reference: '0.9.8-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-ui is vulnerable in Debian 3.0.\nUpgrade to xine-ui_0.9.8-5.1\n');
}
if (deb_check(prefix: 'xine-ui', release: '3.0', reference: '0.9.8-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-ui is vulnerable in Debian woody.\nUpgrade to xine-ui_0.9.8-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
