# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18425);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200506-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-02
(Mailutils: SQL Injection)


    When GNU Mailutils is built with the "mysql" or "postgres" USE
    flag, the sql_escape_string function of the authentication module fails
    to properly escape the "\\" character, rendering it vulnerable to a SQL
    command injection.
  
Impact

    A malicious remote user could exploit this vulnerability to inject
    SQL commands to the underlying database.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1824


Solution: 
    All GNU Mailutils users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/mailutils-0.6-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-02] Mailutils: SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mailutils: SQL Injection');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/mailutils", unaffected: make_list("ge 0.6-r1"), vulnerable: make_list("lt 0.6-r1")
)) { security_warning(0); exit(0); }
