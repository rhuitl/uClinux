# This script was automatically generated from the dsa-199
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steven Christey discovered a cross site scripting vulnerability in
mhonarc, a mail to HTML converter.  Carefully crafted message headers
can introduce cross site scripting when mhonarc is configured to
display all headers lines on the web.  However, it is often useful to
restrict the displayed header lines to To, From and Subject, in which
case the vulnerability cannot be exploited.
This problem has been fixed in version 2.5.2-1.2 for the current
stable distribution (woody), in version 2.4.4-1.2 for the old stable
distribution (potato) and in version 2.5.13-1 for the unstable
distribution (sid).
We recommend that you upgrade your mhonarc package.


Solution : http://www.debian.org/security/2002/dsa-199
Risk factor : High';

if (description) {
 script_id(15036);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "199");
 script_cve_id("CVE-2002-1307");
 script_bugtraq_id(6204);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA199] DSA-199-1 mhonarc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-199-1 mhonarc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mhonarc', release: '2.2', reference: '2.4.4-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian 2.2.\nUpgrade to mhonarc_2.4.4-1.2\n');
}
if (deb_check(prefix: 'mhonarc', release: '3.0', reference: '2.5.2-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian 3.0.\nUpgrade to mhonarc_2.5.2-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
