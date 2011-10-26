# This script was automatically generated from the dsa-049
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Megyer Laszlo report on Bugtraq that the cfingerd daemon as distributed
with Debian GNU/Linux 2.2 was not careful in its logging code. By
combining this with an off-by-one error in the code that copied the
username from an ident response cfingerd could be exploited by a remote
user. Since cfingerd does not drop its root privileges until after
it has determined which user to finger an attacker can gain
root privileges.

This has been fixed in version 1.4.1-1.1, and we recommend that you
upgrade your cfingerd package immediately.

Note: this advisory was previously posted as DSA-048-1 by mistake.



Solution : http://www.debian.org/security/2001/dsa-049
Risk factor : High';

if (description) {
 script_id(14886);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "049");
 script_cve_id("CVE-2001-0609");
 script_bugtraq_id(2576);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA049] DSA-049-1 cfingerd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-049-1 cfingerd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cfingerd', release: '2.2', reference: '1.4.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfingerd is vulnerable in Debian 2.2.\nUpgrade to cfingerd_1.4.1-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
