# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17287);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200503-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-13
(mlterm: Integer overflow vulnerability)


    mlterm is vulnerable to an integer overflow that can be triggered
    by specifying a large image file as a background. This only effects
    users that have compiled mlterm with the \'gtk\' USE flag, which enables
    gdk-pixbuf support.
  
Impact

    An attacker can create a specially-crafted image file which, when
    used as a background by the victim, can lead to the execution of
    arbitrary code with the privileges of the user running mlterm.
  
Workaround

    Re-compile mlterm without the \'gtk\' USE flag.
  
References:
    https://sourceforge.net/project/shownotes.php?release_id=310416


Solution: 
    All mlterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/mlterm-2.9.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-13] mlterm: Integer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mlterm: Integer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-terms/mlterm", unaffected: make_list("ge 2.9.2"), vulnerable: make_list("lt 2.9.2")
)) { security_warning(0); exit(0); }
