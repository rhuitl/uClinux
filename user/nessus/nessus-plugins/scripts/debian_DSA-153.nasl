# This script was automatically generated from the dsa-153
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Joao Gouveia discovered an uninitialized variable which was insecurely
used with file inclusions in the mantis package, a php based bug
tracking system.  The Debian Security Team found even more similar
problems.  When these occasions are exploited, a remote user is able
to execute arbitrary code under the webserver user id on the web
server hosting the mantis system.
Jeroen Latour discovered that Mantis did not check all user input,
especially if they do not come directly from form fields. This opens
up a wide variety of SQL poisoning vulnerabilities on systems without
magic_quotes_gpc enabled.  Most of these vulnerabilities are only
exploitable in a limited manner, since it is no longer possible to
execute multiple queries using one call to mysql_query().  There is
one query which can be tricked into changing an account\'s access
level.
Jeroen Latour also reported that it is possible to instruct Mantis to
show reporters only the bugs that they reported, by setting the
limit_reporters option to ON.  However, when formatting the output
suitable for printing, the program did not check the limit_reporters
option and thus allowed reporters to see the summaries of bugs they
did not report.
Jeroen Latour discovered that the page responsible for displaying a
list of bugs in a particular project, did not check whether the user
actually has access to the project, which is transmitted by a cookie
variable.  It accidentally trusted the fact that only projects
accessible to the user were listed in the drop-down menu.  This
provides a malicious user with an opportunity to display the bugs of a
private project selected.
These problems have been fixed in version 0.17.1-2.2 for the current
stable distribution (woody) and in version 0.17.4a-2 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected, since it doesn\'t contain the mantis package.
Additional information:
We recommend that you upgrade your mantis packages immediately.


Solution : http://www.debian.org/security/2002/dsa-153
Risk factor : High';

if (description) {
 script_id(14990);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "153");
 script_cve_id("CVE-2002-1110", "CVE-2002-1111", "CVE-2002-1112", "CVE-2002-1113", "CVE-2002-1114");
 script_bugtraq_id(5504, 5509, 5510, 5514, 5515, 5563, 5565);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA153] DSA-153-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-153-1 mantis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mantis', release: '3.0', reference: '0.17.1-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian 3.0.\nUpgrade to mantis_0.17.1-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
