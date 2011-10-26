# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21703);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-10
(Cscope: Many buffer overflows)


    Cscope does not verify the length of file names sourced in
    #include statements.
  
Impact

    A user could be enticed to source a carefully crafted file which
    will allow the attacker to execute arbitrary code with the permissions
    of the user running Cscope.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2541


Solution: 
    All Cscope users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/cscope-15.5-r6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-10] Cscope: Many buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cscope: Many buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/cscope", unaffected: make_list("ge 15.5-r6"), vulnerable: make_list("lt 15.5-r6")
)) { security_warning(0); exit(0); }
