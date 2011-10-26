# This script was automatically generated from the dsa-024
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'The FreeBSD team has found a bug in the way new crontabs
were handled which allowed malicious users to display arbitrary crontab files
on the local system. This only affects valid crontab files so it can\'t be used to
get access to /etc/shadow or something. crontab files are not especially secure
anyway, as there are other ways they can leak. No passwords or similar
sensitive data should be in there. We recommend you upgrade your cron
packages.


Solution : http://www.debian.org/security/2001/dsa-024
Risk factor : High';

if (description) {
 script_id(14861);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "024");
 script_cve_id("CVE-2001-0235");
 script_bugtraq_id(2332);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA024] DSA-024-1 cron");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-024-1 cron");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cron', release: '2.2', reference: '3.0pl1-57.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cron is vulnerable in Debian 2.2.\nUpgrade to cron_3.0pl1-57.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
