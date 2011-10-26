# This script was automatically generated from the dsa-152
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Current versions of l2tpd, a layer 2 tunneling client/server program,
forgot to initialize the random generator which made it vulnerable
since all generated random number were 100% guessable.  When dealing
with the size of the value in an attribute value pair, too many bytes
were able to be copied, which could lead into the vendor field being
overwritten.
These problems have been fixed in version 0.67-1.1 for the current
stable distribution (woody) and in version 0.68-1 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected, since it doesn\'t contain the l2tpd package.
We recommend that you upgrade your l2tpd packages.


Solution : http://www.debian.org/security/2002/dsa-152
Risk factor : High';

if (description) {
 script_id(14989);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "152");
 script_cve_id("CVE-2002-0872", "CVE-2002-0873");
 script_bugtraq_id(5451);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA152] DSA-152-1 l2tpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-152-1 l2tpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'l2tpd', release: '3.0', reference: '0.67-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package l2tpd is vulnerable in Debian 3.0.\nUpgrade to l2tpd_0.67-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
