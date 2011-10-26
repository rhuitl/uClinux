# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16406);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200501-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-15
(UnRTF: Buffer overflow)


    An unchecked strcat() in unrtf may overflow the bounds of a static
    buffer.
  
Impact

    Using a specially crafted file, possibly delivered by e-mail or
    over the web, an attacker may execute arbitrary code with the
    permissions of the user running UnRTF.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://tigger.uic.edu/~jlongs2/holes/unrtf.txt


Solution: 
    All unrtf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/unrtf-0.19.3-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-15] UnRTF: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'UnRTF: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/unrtf", unaffected: make_list("ge 0.19.3-r1"), vulnerable: make_list("lt 0.19.3-r1")
)) { security_warning(0); exit(0); }
