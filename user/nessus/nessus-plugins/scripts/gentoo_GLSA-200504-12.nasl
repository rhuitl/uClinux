# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18045);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200504-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-12
(rsnapshot: Local privilege escalation)


    The copy_symlink() subroutine in rsnapshot follows symlinks when
    changing file ownership, instead of changing the ownership of the
    symlink itself.
  
Impact

    Under certain circumstances, local attackers can exploit this
    vulnerability to take ownership of arbitrary files, resulting in local
    privilege escalation.
  
Workaround

    The copy_symlink() subroutine is not called if the cmd_cp parameter has
    been enabled.
  
References:
    http://www.rsnapshot.org/security/2005/001.html


Solution: 
    All rsnapshot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-misc/rsnapshot
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-12] rsnapshot: Local privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsnapshot: Local privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/rsnapshot", unaffected: make_list("ge 1.2.1", "rge 1.1.7"), vulnerable: make_list("lt 1.2.1")
)) { security_hole(0); exit(0); }
