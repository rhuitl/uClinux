# This script was automatically generated from the dsa-016
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Security people at WireX have noticed a temp file creation
bug and the WU-FTPD development team has found a possible format string bug in
wu-ftpd. Both could be remotely exploited, though no such exploit exists
currently.

We recommend you upgrade your wu-ftpd package immediately.


Solution : http://www.debian.org/security/2001/dsa-016
Risk factor : High';

if (description) {
 script_id(14853);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "016");
 script_cve_id("CVE-2001-0187");
 script_bugtraq_id(2189, 2296);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA016] DSA-016-3 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-016-3 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wu-ftpd', release: '2.2', reference: '2.6.0-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian 2.2.\nUpgrade to wu-ftpd_2.6.0-5.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
