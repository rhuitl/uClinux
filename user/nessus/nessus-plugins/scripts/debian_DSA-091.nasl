# This script was automatically generated from the dsa-091
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
If the UseLogin feature is enabled in ssh local users could
pass environment variables (including variables like LD_PRELOAD)
to the login process. This has been fixed by not copying the
environment if UseLogin is enabled.

Please note that the default configuration for Debian does not
have UseLogin enabled.

This has been fixed in version 1:1.2.3-9.4.



Solution : http://www.debian.org/security/2001/dsa-091
Risk factor : High';

if (description) {
 script_id(14928);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "091");
 script_cve_id("CVE-2001-0872");
 script_bugtraq_id(3614);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA091] DSA-091-1 ssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-091-1 ssh");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ssh', release: '2.2', reference: '1.2.3-9.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh is vulnerable in Debian 2.2.\nUpgrade to ssh_1.2.3-9.4\n');
}
if (deb_check(prefix: 'ssh-askpass-gnome', release: '2.2', reference: '1.2.3-9.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-askpass-gnome is vulnerable in Debian 2.2.\nUpgrade to ssh-askpass-gnome_1.2.3-9.4\n');
}
if (deb_check(prefix: 'ssh-askpass-ptk', release: '2.2', reference: '1.2.3-9.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-askpass-ptk is vulnerable in Debian 2.2.\nUpgrade to ssh-askpass-ptk_1.2.3-9.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
