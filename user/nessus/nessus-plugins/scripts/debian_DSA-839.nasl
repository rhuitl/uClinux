# This script was automatically generated from the dsa-839
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Eric Romang discovered an insecurely created temporary file in
apachetop, a realtime monitoring tool for the Apache webserver that
could be exploited with a symlink attack to overwrite arbitrary files
with the user id that runs apachetop.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.12.5-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.12.5-5.
We recommend that you upgrade your apachetop package.


Solution : http://www.debian.org/security/2005/dsa-839
Risk factor : High';

if (description) {
 script_id(19808);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "839");
 script_cve_id("CVE-2005-2660");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA839] DSA-839-1 apachetop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-839-1 apachetop");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apachetop', release: '', reference: '0.12.5-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apachetop is vulnerable in Debian .\nUpgrade to apachetop_0.12.5-5\n');
}
if (deb_check(prefix: 'apachetop', release: '3.1', reference: '0.12.5-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apachetop is vulnerable in Debian 3.1.\nUpgrade to apachetop_0.12.5-1sarge1\n');
}
if (deb_check(prefix: 'apachetop', release: '3.1', reference: '0.12.5-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apachetop is vulnerable in Debian sarge.\nUpgrade to apachetop_0.12.5-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
