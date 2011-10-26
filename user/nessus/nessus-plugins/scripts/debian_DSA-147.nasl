# This script was automatically generated from the dsa-147
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cross-site scripting vulnerability was discovered in mailman, a
software to manage electronic mailing lists.  When a properly crafted
URL is accessed with Internet Explorer (other browsers don\'t seem to
be affected), the resulting webpage is rendered similar to the real
one, but the javascript component is executed as well, which could be
used by an attacker to get access to sensitive information.  The new
version for Debian 2.2 also includes backports of security related
patches from mailman 2.0.11.
This problem has been fixed in version 2.0.11-1woody4 for the current
stable distribution (woody), in version 1.1-10.1 for the old stable
distribution (potato) and in version 2.0.12-1 for the unstable
distribution (sid).
We recommend that you upgrade your mailman package.


Solution : http://www.debian.org/security/2002/dsa-147
Risk factor : High';

if (description) {
 script_id(14984);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "147");
 script_cve_id("CVE-2002-0388", "CVE-2002-0855");
 script_bugtraq_id(4825, 4826, 5298);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA147] DSA-147-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-147-1 mailman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailman', release: '2.2', reference: '1.1-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 2.2.\nUpgrade to mailman_1.1-10.1\n');
}
if (deb_check(prefix: 'mailman', release: '3.0', reference: '2.0.11-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 3.0.\nUpgrade to mailman_2.0.11-1woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
