# This script was automatically generated from the dsa-392
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jens Steube reported two vulnerabilities in webfs, a lightweight HTTP
server for static content.
 CVE-2003-0832 - When virtual hosting is enabled, a remote client
 could specify ".." as the hostname in a request, allowing retrieval
 of directory listings or files above the document root.
 CVE-2003-0833 - A long pathname could overflow a buffer allocated on
 the stack, allowing execution of arbitrary code.  In order to exploit
 this vulnerability, it would be necessary to be able to create
 directories on the server in a location which could be accessed by
 the web server.  In conjunction with CVE-2003-0832, this could be a
 world-writable directory such as /var/tmp.
For the current stable distribution (woody) these problems have been fixed
in version 1.17.2.
For the unstable distribution (sid) these problems have been fixed in
version 1.20.
We recommend that you update your webfs package.


Solution : http://www.debian.org/security/2003/dsa-392
Risk factor : High';

if (description) {
 script_id(15229);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "392");
 script_cve_id("CVE-2003-0832", "CVE-2003-0833");
 script_bugtraq_id(8724, 8726);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA392] DSA-392-1 webfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-392-1 webfs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'webfs', release: '3.0', reference: '1.17.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webfs is vulnerable in Debian 3.0.\nUpgrade to webfs_1.17.2\n');
}
if (deb_check(prefix: 'webfs', release: '3.1', reference: '1.20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webfs is vulnerable in Debian 3.1.\nUpgrade to webfs_1.20\n');
}
if (deb_check(prefix: 'webfs', release: '3.0', reference: '1.17.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webfs is vulnerable in Debian woody.\nUpgrade to webfs_1.17.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
