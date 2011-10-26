# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20358);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-17
(scponly: Multiple privilege escalation issues)


    Max Vozeler discovered that the scponlyc command allows users to
    chroot into arbitrary directories. Furthermore, Pekka Pessi reported
    that scponly insufficiently validates command-line parameters to a scp
    or rsync command.
  
Impact

    A local attacker could gain root privileges by chrooting into
    arbitrary directories containing hardlinks to setuid programs. A remote
    scponly user could also send malicious parameters to a scp or rsync
    command that would allow to escape the shell restrictions and execute
    arbitrary programs.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://sublimation.org/scponly/index.html#relnotes


Solution: 
    All scponly users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/scponly-4.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-17] scponly: Multiple privilege escalation issues");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'scponly: Multiple privilege escalation issues');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/scponly", unaffected: make_list("ge 4.2"), vulnerable: make_list("lt 4.2")
)) { security_hole(0); exit(0); }
