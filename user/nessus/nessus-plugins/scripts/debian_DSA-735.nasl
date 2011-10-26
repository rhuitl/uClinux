# This script was automatically generated from the dsa-735
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A local user who has been granted permission to run commands via sudo
could run arbitrary commands as a privileged user due to a flaw in
sudo\'s pathname validation. This bug only affects configurations which
have restricted user configurations prior to an ALL directive in the
configuration file. A workaround is to move any ALL directives to the
beginning of the sudoers file; see the advisory at
http://www.sudo.ws/sudo/alerts/path_race.html / for more information.
For the old stable Debian distribution (woody), this problem has been
fixed in version 1.6.6-1.3woody1.
For the current stable distribution
(sarge), this problem has been fixed in version 1.6.8p7-1.1sarge1.
Note that packages are not yet ready for certain architectures; these
will be released as they become available.
We recommend that you upgrade your sudo package.


Solution : http://www.debian.org/security/2005/dsa-735
Risk factor : High';

if (description) {
 script_id(18603);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "735");
 script_cve_id("CVE-2005-1993");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA735] DSA-735-1 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-735-1 sudo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 3.0.\nUpgrade to sudo_1.6.6-1.3woody1\n');
}
if (deb_check(prefix: 'sudo', release: '3.1', reference: '1.6.8p7-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 3.1.\nUpgrade to sudo_1.6.8p7-1.1sarge1\n');
}
if (deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian woody.\nUpgrade to sudo_1.6.6-1.3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
