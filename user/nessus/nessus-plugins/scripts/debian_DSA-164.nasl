# This script was automatically generated from the dsa-164
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem in cacti, a PHP based frontend to rrdtool for monitoring
systems and services, has been discovered.  This could lead into cacti
executing arbitrary program code under the user id of the web server.
This problem, however, is only persistent to users who already have
administrator privileges in the cacti system.
This problem has been fixed by removing any dollar signs and backticks
from the title string in version 0.6.7-2.1 for the current stable
distribution (woody) and in version 0.6.8a-2 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn\'t contain the cacti package.
We recommend that you upgrade your cacti package immediately.


Solution : http://www.debian.org/security/2002/dsa-164
Risk factor : High';

if (description) {
 script_id(15001);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "164");
 script_cve_id("CVE-2002-1477", "CVE-2002-1478");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA164] DSA-164-1 cacti");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-164-1 cacti");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cacti', release: '3.0', reference: '0.6.7-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cacti is vulnerable in Debian 3.0.\nUpgrade to cacti_0.6.7-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
