# This script was automatically generated from the dsa-105
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The version of enscript (a tool to convert ASCII text to different
formats) in potato has been found to create temporary files insecurely.
This has been fixed in version 1.6.2-4.1.


Solution : http://www.debian.org/security/2002/dsa-105
Risk factor : High';

if (description) {
 script_id(14942);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "105");
 script_cve_id("CVE-2002-0044");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA105] DSA-105-1 enscript");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-105-1 enscript");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'enscript', release: '2.2', reference: '1.6.2-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package enscript is vulnerable in Debian 2.2.\nUpgrade to enscript_1.6.2-4.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
