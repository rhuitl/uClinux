# This script was automatically generated from the dsa-023
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '

People at WireX have found several potential insecure uses of temporary files in programs provided by INN2. Some of them only lead to a vulnerability to symlink attacks if the temporary directory was set to /tmp or /var/tmp, which is the case in many installations, at least in Debian packages. An attacker could overwrite any file owned by the news system administrator, i.e. owned by news.news.
Michal Zalewski found an exploitable buffer overflow with regard to cancel messages and their verification. This bug did only show up if "verifycancels" was enabled in inn.conf which is not the default and has been disrecommended by upstream.
Andi Kleen found a bug in INN2 that makes innd crash for two byte headers. There is a chance this can only be exploited with uucp.

We recommend you upgrade your inn2 packages immediately.


Solution : http://www.debian.org/security/2001/dsa-023
Risk factor : High';

if (description) {
 script_id(14860);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "023");
 script_cve_id("CVE-2001-0361");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA023] DSA-023-1 inn2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-023-1 inn2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'inn2', release: '2.2', reference: '2.2.2.2000.01.31-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package inn2 is vulnerable in Debian 2.2.\nUpgrade to inn2_2.2.2.2000.01.31-4.1\n');
}
if (deb_check(prefix: 'inn2-dev', release: '2.2', reference: '2.2.2.2000.01.31-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package inn2-dev is vulnerable in Debian 2.2.\nUpgrade to inn2-dev_2.2.2.2000.01.31-4.1\n');
}
if (deb_check(prefix: 'inn2-inews', release: '2.2', reference: '2.2.2.2000.01.31-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package inn2-inews is vulnerable in Debian 2.2.\nUpgrade to inn2-inews_2.2.2.2000.01.31-4.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
