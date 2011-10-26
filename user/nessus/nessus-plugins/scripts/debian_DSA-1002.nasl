# This script was automatically generated from the dsa-1002
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in webcalendar,
a PHP based multi-user calendar.  The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities:
    Multiple SQL injection vulnerabilities allow remote attackers to
    execute arbitrary SQL commands.
    Missing input sanitising allows an attacker to overwrite local
    files.
    A CRLF injection vulnerability allows remote attackers to modify
    HTTP headers and conduct HTTP response splitting attacks.
The old stable distribution (woody) does not contain webcalendar packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.45-4sarge3.
For the unstable distribution (sid) these problems have been fixed in
version 1.0.2-1.
We recommend that you upgrade your webcalendar package.


Solution : http://www.debian.org/security/2006/dsa-1002
Risk factor : High';

if (description) {
 script_id(22544);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1002");
 script_cve_id("CVE-2005-3949", "CVE-2005-3961", "CVE-2005-3982");
 script_bugtraq_id(15606, 15608, 15662, 15673);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1002] DSA-1002-1 webcalendar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1002-1 webcalendar");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'webcalendar', release: '', reference: '1.0.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian .\nUpgrade to webcalendar_1.0.2-1\n');
}
if (deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian 3.1.\nUpgrade to webcalendar_0.9.45-4sarge3\n');
}
if (deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian sarge.\nUpgrade to webcalendar_0.9.45-4sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
