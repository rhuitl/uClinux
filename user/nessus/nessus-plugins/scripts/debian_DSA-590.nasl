# This script was automatically generated from the dsa-590
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Khan Shirani discovered a format string vulnerability in gnats, the
GNU problem report management system.  This problem may be exploited
to execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 3.999.beta1+cvs20020303-2.
For the unstable distribution (sid) this problem has been fixed in
version 4.0-7.
We recommend that you upgrade your gnats package.


Solution : http://www.debian.org/security/2004/dsa-590
Risk factor : High';

if (description) {
 script_id(15688);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "590");
 script_cve_id("CVE-2004-0623");
 script_bugtraq_id(10609);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA590] DSA-590-1 gnats");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-590-1 gnats");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnats', release: '3.0', reference: '3.999.beta1+cvs20020303-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnats is vulnerable in Debian 3.0.\nUpgrade to gnats_3.999.beta1+cvs20020303-2\n');
}
if (deb_check(prefix: 'gnats-user', release: '3.0', reference: '3.999.beta1+cvs20020303-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnats-user is vulnerable in Debian 3.0.\nUpgrade to gnats-user_3.999.beta1+cvs20020303-2\n');
}
if (deb_check(prefix: 'gnats', release: '3.1', reference: '4.0-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnats is vulnerable in Debian 3.1.\nUpgrade to gnats_4.0-7\n');
}
if (deb_check(prefix: 'gnats', release: '3.0', reference: '3.999.beta1+cvs20020303-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnats is vulnerable in Debian woody.\nUpgrade to gnats_3.999.beta1+cvs20020303-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
