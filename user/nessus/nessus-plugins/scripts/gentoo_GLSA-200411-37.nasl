# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-37.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15843);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200411-37");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-37
(Open DC Hub: Remote code execution)


    Donato Ferrante discovered a buffer overflow vulnerability in the
    RedirectAll command of the Open DC Hub.
  
Impact

    Upon exploitation, a remote user with administrative privileges
    can execute arbitrary code on the system running the Open DC Hub.
  
Workaround

    Only give administrative rights to trusted users.
  
References:
    http://archives.neohapsis.com/archives/fulldisclosure/2004-11/1115.html


Solution: 
    All Open DC Hub users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-p2p/opendchub-0.7.14-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-37] Open DC Hub: Remote code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Open DC Hub: Remote code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-p2p/opendchub", unaffected: make_list("ge 0.7.14-r2"), vulnerable: make_list("lt 0.7.14-r2")
)) { security_hole(0); exit(0); }
