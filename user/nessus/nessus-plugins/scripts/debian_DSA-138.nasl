# This script was automatically generated from the dsa-138
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem was found in gallery (a web-based photo album toolkit): it
was possible to pass in the GALLERY_BASEDIR variable remotely. This
made it possible to execute commands under the uid of web-server.
This has been fixed in version 1.2.5-7 of the Debian package and upstream
version 1.3.1.


Solution : http://www.debian.org/security/2002/dsa-138
Risk factor : High';

if (description) {
 script_id(14975);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "138");
 script_cve_id("CVE-2002-1412");
 script_bugtraq_id(5375);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA138] DSA-138-1 gallery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-138-1 gallery");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-7.woody.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian 3.0.\nUpgrade to gallery_1.2.5-7.woody.0\n');
}
if (w) { security_hole(port: 0, data: desc); }
