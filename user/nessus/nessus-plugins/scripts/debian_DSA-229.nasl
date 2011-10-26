# This script was automatically generated from the dsa-229
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jouko Pynnonen discovered a problem with IMP, a web based IMAP mail
program.  Using carefully crafted URLs a remote attacker is able to
inject SQL code into SQL queries without proper user authentication.
Even though results of SQL queries aren\'t directly readable from the
screen, an attacker might update their mail signature to contain wanted
query results and then view it on the preferences page of IMP.
The impact of SQL injection depends heavily on the underlying database
and its configuration.  If PostgreSQL is used, it\'s possible to
execute multiple complete SQL queries separated by semicolons.  The
database contains session id\'s so the attacker might hijack sessions
of people currently logged in and read their mail.  In the worst case,
if the hordemgr user has the required privilege to use the COPY SQL
command (found in PostgreSQL at least), a remote user may read or
write to any file the database user (postgres) can.  The attacker may
then be able to run arbitrary shell commands by writing them to the
postgres user\'s ~/.psqlrc; they\'d be run when the user starts the psql
command which under some configurations happens regularly from a cron
script.
For the current stable distribution (woody) this problem has been
fixed in version 2.2.6-5.1.
For the old stable distribution (potato) this problem has been
fixed in version 2.2.6-0.potato.5.1.
For the unstable distribution (sid) this problem have been fixed in
version 2.2.6-7.
We recommend that you upgrade your IMP packages.


Solution : http://www.debian.org/security/2003/dsa-229
Risk factor : High';

if (description) {
 script_id(15066);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "229");
 script_cve_id("CVE-2003-0025");
 script_bugtraq_id(6559);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA229] DSA-229-1 imp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-229-1 imp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'imp', release: '2.2', reference: '2.2.6-0.potato.5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imp is vulnerable in Debian 2.2.\nUpgrade to imp_2.2.6-0.potato.5.1\n');
}
if (deb_check(prefix: 'imp', release: '3.0', reference: '2.2.6-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imp is vulnerable in Debian 3.0.\nUpgrade to imp_2.2.6-5.1\n');
}
if (deb_check(prefix: 'imp', release: '3.1', reference: '2.2.6-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imp is vulnerable in Debian 3.1.\nUpgrade to imp_2.2.6-7\n');
}
if (deb_check(prefix: 'imp', release: '2.2', reference: '2.2.6-0.potato.5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imp is vulnerable in Debian potato.\nUpgrade to imp_2.2.6-0.potato.5.1\n');
}
if (deb_check(prefix: 'imp', release: '3.0', reference: '2.2.6-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imp is vulnerable in Debian woody.\nUpgrade to imp_2.2.6-5.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
