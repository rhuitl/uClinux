# This script was automatically generated from the dsa-194
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A set of buffer overflows have been discovered in masqmail, a mail
transport agent for hosts without permanent internet connection.  In
addition to this privileges were dropped only after reading a user
supplied configuration file.  Together this could be exploited to gain
unauthorized root access to the machine on which masqmail is
installed.
These problems have been fixed in version 0.1.16-2.1 for the current
stable distribution (woody) and in version 0.2.15-1 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn\'t contain a masqmail package.
We recommend that you upgrade your masqmail package immediately.


Solution : http://www.debian.org/security/2002/dsa-194
Risk factor : High';

if (description) {
 script_id(15031);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "194");
 script_cve_id("CVE-2002-1279");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA194] DSA-194-1 masqmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-194-1 masqmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'masqmail', release: '3.0', reference: '0.1.16-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package masqmail is vulnerable in Debian 3.0.\nUpgrade to masqmail_0.1.16-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
