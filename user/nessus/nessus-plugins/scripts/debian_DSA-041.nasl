# This script was automatically generated from the dsa-041
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Christer Öberg of Wkit Security AB found a problem in joe
(Joe\'s Own Editor). joe will look for a configuration file in three locations:
The current directory, the users homedirectory ($HOME) and in /etc/joe. Since
the configuration file can define commands joe will run (for example to check
spelling) reading it from the current directory can be dangerous: An attacker
can leave a .joerc file in a writable directory, which would be read when a
unsuspecting user starts joe in that directory.

This has been fixed in version 2.8-15.3 and we recommend that you upgrade
your joe package immediately.


Solution : http://www.debian.org/security/2001/dsa-041
Risk factor : High';

if (description) {
 script_id(14878);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "041");
 script_cve_id("CVE-2001-0289");
 script_bugtraq_id(2437);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA041] DSA-041-1 joe");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-041-1 joe");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'joe', release: '2.2', reference: '2.8-15.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package joe is vulnerable in Debian 2.2.\nUpgrade to joe_2.8-15.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
