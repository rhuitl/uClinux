# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22168);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-10
(pike: SQL injection vulnerability)


    Some input is not properly sanitised before being used in a SQL
    statement in the underlying PostgreSQL database.
  
Impact

    A remote attacker could provide malicious input to a pike program,
    which might result in the execution of arbitrary SQL statements.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/20494/


Solution: 
    All pike users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/pike-7.6.86"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-10] pike: SQL injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pike: SQL injection vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/pike", unaffected: make_list("ge 7.6.86"), vulnerable: make_list("lt 7.6.86")
)) { security_warning(0); exit(0); }
