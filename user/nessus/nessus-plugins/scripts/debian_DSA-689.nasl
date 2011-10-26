# This script was automatically generated from the dsa-689
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Graham Dumpleton discovered a flaw which can affect anyone using the
publisher handle of the Apache Software Foundation\'s mod_python.  The
publisher handle lets you publish objects inside modules to make them
callable via URL.  The flaw allows a carefully crafted URL to obtain
extra information that should not be visible (information leak).
For the stable distribution (woody) this problem has been fixed in
version 2.7.8-0.0woody5.
For the unstable distribution (sid) this problem has been fixed in
version 2.7.10-4 of libapache-mod-python and in version 3.1.3-3 of
libapache2-mod-python.
We recommend that you upgrade your libapache-mod-python package.


Solution : http://www.debian.org/security/2005/dsa-689
Risk factor : High';

if (description) {
 script_id(17197);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "689");
 script_cve_id("CVE-2005-0088");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA689] DSA-689-1 libapache-mod-python");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-689-1 libapache-mod-python");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-mod-python', release: '3.0', reference: '2.7.8-0.0woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-python is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-python_2.7.8-0.0woody5\n');
}
if (deb_check(prefix: 'libapache-mod-python', release: '3.1', reference: '2.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-python is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-python_2.7\n');
}
if (deb_check(prefix: 'libapache-mod-python', release: '3.0', reference: '2.7.8-0.0woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-python is vulnerable in Debian woody.\nUpgrade to libapache-mod-python_2.7.8-0.0woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
