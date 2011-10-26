# This script was automatically generated from the dsa-025
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'A former security upload of OpenSSH lacked support for PAM
which lead to people not being able to log onto their server. This was
only a problem on the sparc architecture. We recommend you
upgrade your ssh packages on sparc.


Solution : http://www.debian.org/security/2001/dsa-025
Risk factor : High';

if (description) {
 script_id(14862);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "025");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA025] DSA-025-2 openssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-025-2 openssh");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ssh', release: '2.2', reference: '1.2.3-9.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh is vulnerable in Debian 2.2.\nUpgrade to ssh_1.2.3-9.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
