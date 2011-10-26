# This script was automatically generated from the dsa-028
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Styx has reported that the program `man\' mistakenly passes
malicious strings (i.e. containing format characters) through routines that
were not meant to use them as format strings. Since this could cause a
segmentation fault and privileges were not dropped it may lead to an exploit
for the \'man\' user. 

We recommend you upgrade your man-db package immediately.


Solution : http://www.debian.org/security/2001/dsa-028
Risk factor : High';

if (description) {
 script_id(14865);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "028");
 script_cve_id("CVE-2001-0193");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA028] DSA-028-1 man-db");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-028-1 man-db");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'man-db', release: '2.2', reference: '2.3.16-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package man-db is vulnerable in Debian 2.2.\nUpgrade to man-db_2.3.16-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
