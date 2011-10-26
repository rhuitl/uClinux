# This script was automatically generated from the dsa-452
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The Apache Software Foundation announced that some versions of
mod_python contain a bug which, when processing a request with a
malformed query string, could cause the corresponding Apache child to
crash.  This bug could be exploited by a remote attacker to cause a
denial of service.
For the current stable distribution (woody) this problem has been
fixed in version 2:2.7.8-0.0woody2.
For the unstable distribution (sid), this problem has been fixed in
version 2:2.7.10-1.
We recommend that you update your libapache-mod-python package.


Solution : http://www.debian.org/security/2004/dsa-452
Risk factor : High';

if (description) {
 script_id(15289);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "452");
 script_cve_id("CVE-2003-0973");
 script_bugtraq_id(9129);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA452] DSA-452-1 libapache-mod-python");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-452-1 libapache-mod-python");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-mod-python', release: '3.0', reference: '2.7.8-0.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-python is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-python_2.7.8-0.0woody2\n');
}
if (deb_check(prefix: 'libapache-mod-python', release: '3.1', reference: '2.7.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-python is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-python_2.7.10-1\n');
}
if (deb_check(prefix: 'libapache-mod-python', release: '3.0', reference: '2.7.8-0.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-python is vulnerable in Debian woody.\nUpgrade to libapache-mod-python_2.7.8-0.0woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
