# This script was automatically generated from the dsa-027
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '

Versions of OpenSSH prior to 2.3.0 are vulnerable to a remote arbitrary
memory overwrite attack which may lead to a root exploit.
CORE-SDI has described a problem with regards to RSA key exchange and a
Bleichenbacher attack to gather the session key from an ssh session. 

Both of these issues have been corrected in our ssh package 1.2.3-9.2.

We recommend you upgrade your openssh package immediately.


Solution : http://www.debian.org/security/2001/dsa-027
Risk factor : High';

if (description) {
 script_id(14864);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "027");
 script_cve_id("CVE-2001-0361");
 script_bugtraq_id(2344);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA027] DSA-027-1 OpenSSH");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-027-1 OpenSSH");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ssh', release: '2.2', reference: '1.2.3-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh is vulnerable in Debian 2.2.\nUpgrade to ssh_1.2.3-9.2\n');
}
if (deb_check(prefix: 'ssh-askpass-gnome', release: '2.2', reference: '1.2.3-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-askpass-gnome is vulnerable in Debian 2.2.\nUpgrade to ssh-askpass-gnome_1.2.3-9.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
