# This script was automatically generated from the dsa-180
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Thorsten Kukuck discovered a problem in the ypserv program which is
part of the Network Information Services (NIS).  A memory leak in all
versions of ypserv prior to 2.5 is remotely exploitable.  When a
malicious user could request a non-existing map the server will leak
parts of an old domainname and mapname.
This problem has been fixed in version 3.9-6.1 for the current stable
distribution (woody), in version 3.8-2.1 for the old stable
distribution (potato) and in version 3.9-6.2 for the unstable
distribution (sid).
We recommend that you upgrade your nis package.


Solution : http://www.debian.org/security/2002/dsa-180
Risk factor : High';

if (description) {
 script_id(15017);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "180");
 script_cve_id("CVE-2002-1232");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA180] DSA-180-1 nis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-180-1 nis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nis', release: '2.2', reference: '3.8-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nis is vulnerable in Debian 2.2.\nUpgrade to nis_3.8-2.1\n');
}
if (deb_check(prefix: 'nis', release: '3.0', reference: '3.9-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nis is vulnerable in Debian 3.0.\nUpgrade to nis_3.9-6.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
