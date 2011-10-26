# This script was automatically generated from the dsa-328
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
webfs, a lightweight HTTP server for static content, contains a buffer
overflow whereby a long Request-URI in an HTTP request could cause
arbitrary code to be executed.
For the stable distribution (woody) this problem has been fixed in
version 1.17.1.
The old stable distribution (potato) does not contain a webfs package.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your webfs package.


Solution : http://www.debian.org/security/2003/dsa-328
Risk factor : High';

if (description) {
 script_id(15165);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "328");
 script_cve_id("CVE-2003-0445");
 script_bugtraq_id(7990);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA328] DSA-328-1 webfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-328-1 webfs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'webfs', release: '3.0', reference: '1.17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webfs is vulnerable in Debian 3.0.\nUpgrade to webfs_1.17.1\n');
}
if (deb_check(prefix: 'webfs', release: '3.0', reference: '1.17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webfs is vulnerable in Debian woody.\nUpgrade to webfs_1.17.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
