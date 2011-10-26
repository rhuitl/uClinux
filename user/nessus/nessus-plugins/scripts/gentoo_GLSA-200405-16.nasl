# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14502);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200405-16");
 script_xref(name: "CERT", value: "CA-2000-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-16
(Multiple XSS Vulnerabilities in SquirrelMail)


    Several unspecified cross-site scripting (XSS) vulnerabilities and a well
    hidden SQL injection vulnerability were found. An XSS attack allows an
    attacker to insert malicious code into a web-based application.
    SquirrelMail does not check for code when parsing variables received via
    the URL query string.
  
Impact

    One of the XSS vulnerabilities could be exploited by an attacker to steal
    cookie-based authentication credentials from the user\'s browser. The SQL
    injection issue could potentially be used by an attacker to run arbitrary
    SQL commands inside the SquirrelMail database with privileges of the
    SquirrelMail database user.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to version 1.4.3_rc1 or higher of SquirrelMail.
  
References:
    http://sourceforge.net/mailarchive/forum.php?thread_id=4199060&forum_id=1988
    http://www.securityfocus.com/bid/10246/
    http://www.cert.org/advisories/CA-2000-02.html


Solution: 
    All SquirrelMail users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-mail/squirrelmail-1.4.3_rc1"
    # emerge ">=net-mail/squirrelmail-1.4.3_rc1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-16] Multiple XSS Vulnerabilities in SquirrelMail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple XSS Vulnerabilities in SquirrelMail');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/squirrelmail", unaffected: make_list("ge 1.4.3_rc1"), vulnerable: make_list("lt 1.4.3_rc1")
)) { security_warning(0); exit(0); }
