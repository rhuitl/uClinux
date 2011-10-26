# This script was automatically generated from the dsa-946
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The former correction to vulnerabilities in the sudo package worked
fine but were too strict for some environments.  Therefore we have
reviewed the changes again and allowed some environment variables to
go back into the privileged execution environment.  Hence, this
update.
The configuration option "env_reset" is now activated by default.
It will preserve only the environment variables HOME, LOGNAME, PATH,
SHELL, TERM, DISPLAY, XAUTHORITY, XAUTHORIZATION, LANG, LANGUAGE,
LC_*, and USER in addition to the separate SUDO_* variables.
For completeness please find below the original advisory text:
It has been discovered that sudo, a privileged program, that provides
limited super user privileges to specific users, passes several
environment variables to the program that runs with elevated
privileges.  In the case of include paths (e.g. for Perl, Python, Ruby
or other scripting languages) this can cause arbitrary code to be
executed as privileged user if the attacker points to a manipulated
version of a system library.
This update alters the former behaviour of sudo and limits the number
of supported environment variables to LC_*, LANG, LANGUAGE and TERM.
Additional variables are only passed through when set as env_check in
/etc/sudoers, which might be required for some scripts to continue to
work.
For the old stable distribution (woody) this problem has been fixed in
version 1.6.6-1.6.
For the stable distribution (sarge) this problem has been fixed in
version 1.6.8p7-1.4.
For the unstable distribution (sid) the same behaviour will be
implemented soon.
We recommend that you upgrade your sudo package.  For unstable
"Defaults = env_reset" need to be added to /etc/sudoers manually.


Solution : http://www.debian.org/security/2006/dsa-946
Risk factor : High';

if (description) {
 script_id(22812);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "946");
 script_cve_id("CVE-2005-4158", "CVE-2006-0151");
 script_bugtraq_id(16184);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA946] DSA-946-2 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-946-2 sudo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 3.0.\nUpgrade to sudo_1.6.6-1.6\n');
}
if (deb_check(prefix: 'sudo', release: '3.1', reference: '1.6.8p7-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 3.1.\nUpgrade to sudo_1.6.8p7-1.4\n');
}
if (deb_check(prefix: 'sudo', release: '3.1', reference: '1.6.8p7-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian sarge.\nUpgrade to sudo_1.6.8p7-1.4\n');
}
if (deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian woody.\nUpgrade to sudo_1.6.6-1.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
