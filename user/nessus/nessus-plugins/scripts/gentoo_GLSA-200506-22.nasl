# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18549);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200506-22");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-22
(sudo: Arbitrary command execution)


    The sudoers file is used to define the actions sudo users are
    permitted to perform. Charles Morris discovered that a specific layout
    of the sudoers file could cause the results of an internal check to be
    clobbered, leaving sudo vulnerable to a race condition.
  
Impact

    Successful exploitation would permit a local sudo user to execute
    arbitrary commands as another user.
  
Workaround

    Reorder the sudoers file using the visudo utility to ensure the
    \'ALL\' pseudo-command precedes other command definitions.
  
References:
    http://www.sudo.ws/sudo/alerts/path_race.html


Solution: 
    All sudo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/sudo-1.6.8_p9"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-22] sudo: Arbitrary command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sudo: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/sudo", unaffected: make_list("ge 1.6.8_p9"), vulnerable: make_list("lt 1.6.8_p9")
)) { security_warning(0); exit(0); }
