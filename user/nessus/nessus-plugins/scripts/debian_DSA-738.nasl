# This script was automatically generated from the dsa-738
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in the way that Razor parses certain
email headers that could potentially be used to crash the Razor program,
causing a denial of service.
For the stable distribution (sarge), this problem has been fixed in
version 2.670-1sarge2. 
The old stable distribution (woody) is not affected by this issue.
We recommend that you upgrade your razor package.


Solution : http://www.debian.org/security/2005/dsa-738
Risk factor : High';

if (description) {
 script_id(18630);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "738");
 script_cve_id("CVE-2005-2024");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA738] DSA-738-1 razor");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-738-1 razor");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'razor', release: '3.1', reference: '2.670-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package razor is vulnerable in Debian 3.1.\nUpgrade to razor_2.670-1sarge2\n');
}
if (deb_check(prefix: 'razor', release: '3.1', reference: '2.670-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package razor is vulnerable in Debian sarge.\nUpgrade to razor_2.670-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
