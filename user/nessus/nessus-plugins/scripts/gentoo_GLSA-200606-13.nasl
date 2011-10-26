# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21706);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-13");
 script_cve_id("CVE-2006-2753");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-13
(MySQL: SQL Injection)


    MySQL is vulnerable to an injection flaw in mysql_real_escape() when
    used with multi-byte characters.
  
Impact

    Due to a flaw in the multi-byte character process, an attacker is still
    able to inject arbitary SQL statements into the MySQL server for
    execution.
  
Workaround

    There are a few workarounds available: NO_BACKSLASH_ESCAPES mode as a
    workaround for a bug in mysql_real_escape_string(): SET
    sql_mode=\'NO_BACKSLASH_ESCAPES\'; SET GLOBAL
    sql_mode=\'NO_BACKSLASH_ESCAPES\'; and server command line options:
    --sql-mode=NO_BACKSLASH_ESCAPES.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2753


Solution: 
    All MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-4.1.20"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-13] MySQL: SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: SQL Injection');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 5.0.22", "rge 4.1.20", "lt 4.1"), vulnerable: make_list("lt 5.0.22")
)) { security_warning(0); exit(0); }
