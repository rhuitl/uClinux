# This script was automatically generated from the dsa-198
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in nullmailer, a simple relay-only mail
transport agent for hosts that relay mail to a fixed set of smart
relays.  When a mail is to be delivered locally to a user that doesn\'t
exist, nullmailer tries to deliver it, discovers a user unknown error
and stops delivering.  Unfortunately, it stops delivering entirely,
not only this mail.  Hence, it\'s very easy to craft a denial of service.
This problem has been fixed in version 1.00RC5-16.1woody2 for the
current stable distribution (woody) and in version 1.00RC5-17 for the
unstable distribution (sid).  The old stable distribution (potato)
does not contain a nullmailer package.
We recommend that you upgrade your nullmailer package.


Solution : http://www.debian.org/security/2002/dsa-198
Risk factor : High';

if (description) {
 script_id(15035);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "198");
 script_cve_id("CVE-2002-1313");
 script_bugtraq_id(6193);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA198] DSA-198-1 nullmailer");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-198-1 nullmailer");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nullmailer', release: '3.0', reference: '1.00RC5-16.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nullmailer is vulnerable in Debian 3.0.\nUpgrade to nullmailer_1.00RC5-16.1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
