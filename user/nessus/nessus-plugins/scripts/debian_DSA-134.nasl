# This script was automatically generated from the dsa-134
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
ISS X-Force released an advisory about an OpenSSH "Remote Challenge
Vulnerability". Unfortunately, the advisory was incorrect on some
points, leading to widespread confusion about the impact of this
vulnerability. No version of OpenSSH in Debian is affected by the
SKEY and BSD_AUTH authentication methods described in the ISS
advisory. However, Debian does include OpenSSH servers with the PAM
feature described as vulnerable in the later advisory by the OpenSSH
team. (This vulnerable feature is authentication using PAM via the
keyboard-interactive mechanism [kbdint].) This vulnerability affects
OpenSSH versions 2.3.1 through 3.3. No exploit is currently known for
the PAM/kbdint vulnerability, but the details are publicly known. All
of these vulnerabilities were corrected in OpenSSH 3.4.
In addition to the vulnerabilities fixes outlined above, our OpenSSH
packages version 3.3 and higher support the new privilege separation
feature from Niels Provos, which changes ssh to use a separate
non-privileged process to handle most of the work. Vulnerabilities in
the unprivileged parts of OpenSSH will lead to compromise of an
unprivileged account restricted to an empty chroot, rather than a
direct root compromise. Privilege separation should help to mitigate
the risks of any future OpenSSH compromise.
Debian 2.2 (potato) shipped with an ssh package based on OpenSSH
1.2.3, and is not vulnerable to the vulnerabilities covered by this
advisory. Users still running a version 1.2.3 ssh package do not have
an immediate need to upgrade to OpenSSH 3.4. Users who upgraded to the
OpenSSH version 3.3 packages released in previous iterations of
DSA-134 should upgrade to the new version 3.4 OpenSSH packages, as the
version 3.3 packages are vulnerable. We suggest that users running
OpenSSH 1.2.3 consider a move to OpenSSH 3.4 to take advantage of the
privilege separation feature. (Though, again, we have no specific
knowledge of any vulnerability in OpenSSH 1.2.3. Please carefully read
the caveats listed below before upgrading from OpenSSH 1.2.3.) We
recommend that any users running a back-ported version of OpenSSH
version 2.0 or higher on potato move to OpenSSH 3.4.
The current pre-release version of Debian (woody) includes an OpenSSH
version 3.0.2p1 package (ssh), which is vulnerable to the PAM/kbdint
problem described above. We recommend that users upgrade to OpenSSH
3.4 and enable privilege separation. Please carefully read the release
notes below before upgrading. Updated packages for ssh-krb5 (an
OpenSSH package supporting kerberos authentication) are currently
being developed. Users who cannot currently upgrade their OpenSSH
packages may work around the known vulnerabilities by disabling the
vulnerable features: make sure the following lines are uncommented and
present in /etc/ssh/sshd_config and restart ssh

  PAMAuthenticationViaKbdInt no
  ChallengeResponseAuthentication no


There should be no other PAMAuthenticationViaKbdInt or
ChallengeResponseAuthentication entries in sshd_config.
That concludes the vulnerability section of this advisory. What
follows are r
[...]

Solution : http://www.debian.org/security/2002/dsa-134
Risk factor : High';

if (description) {
 script_id(14971);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0011");
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "134");
 script_cve_id("CVE-2002-0639", "CVE-2002-0640");
 script_bugtraq_id(5093);
 script_xref(name: "CERT", value: "369347");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA134] DSA-134-4 ssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-134-4 ssh");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '2.2', reference: '0.9.6c-0.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 2.2.\nUpgrade to libssl-dev_0.9.6c-0.potato.1\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '2.2', reference: '0.9.6c-0.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 2.2.\nUpgrade to libssl0.9.6_0.9.6c-0.potato.1\n');
}
if (deb_check(prefix: 'openssl', release: '2.2', reference: '0.9.6c-0.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 2.2.\nUpgrade to openssl_0.9.6c-0.potato.1\n');
}
if (deb_check(prefix: 'ssh', release: '2.2', reference: '3.4p1-0.0potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh is vulnerable in Debian 2.2.\nUpgrade to ssh_3.4p1-0.0potato1\n');
}
if (deb_check(prefix: 'ssh-askpass-gnome', release: '2.2', reference: '3.4p1-0.0potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-askpass-gnome is vulnerable in Debian 2.2.\nUpgrade to ssh-askpass-gnome_3.4p1-0.0potato1\n');
}
if (deb_check(prefix: 'ssleay', release: '2.2', reference: '0.9.6c-0.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 2.2.\nUpgrade to ssleay_0.9.6c-0.potato.1\n');
}
if (deb_check(prefix: 'ssh', release: '3.0', reference: '3.4p1-0.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh is vulnerable in Debian 3.0.\nUpgrade to ssh_3.4p1-0.0woody1\n');
}
if (deb_check(prefix: 'ssh-askpass-gnome', release: '3.0', reference: '3.4p1-0.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-askpass-gnome is vulnerable in Debian 3.0.\nUpgrade to ssh-askpass-gnome_3.4p1-0.0woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
