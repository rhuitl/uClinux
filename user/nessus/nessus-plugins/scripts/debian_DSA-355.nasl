# This script was automatically generated from the dsa-355
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Larry Nguyen discovered a cross site scripting vulnerability in gallery,
a web-based photo album written in php.  This security flaw can allow a
malicious user to craft a URL that executes Javascript code on your
website.
For the current stable distribution (woody) this problem has been fixed
in version 1.25-8woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.3.4-3.
We recommend that you update your gallery package.


Solution : http://www.debian.org/security/2003/dsa-355
Risk factor : High';

if (description) {
 script_id(15192);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "355");
 script_cve_id("CVE-2003-0614");
 script_bugtraq_id(8288);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA355] DSA-355-1 gallery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-355-1 gallery");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian 3.0.\nUpgrade to gallery_1.2.5-8woody1\n');
}
if (deb_check(prefix: 'gallery', release: '3.1', reference: '1.3.4-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian 3.1.\nUpgrade to gallery_1.3.4-3\n');
}
if (deb_check(prefix: 'gallery', release: '3.0', reference: '1.25-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian woody.\nUpgrade to gallery_1.25-8woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
