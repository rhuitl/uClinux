# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20418);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-08
(Blender: Heap-based buffer overflow)


    Damian Put has reported a flaw due to an integer overflow in the
    "get_bhead()" function, leading to a heap overflow when processing
    malformed ".blend" files.
  
Impact

    A remote attacker could entice a user into opening a specially
    crafted ".blend" file, resulting in the execution of arbitrary code
    with the permissions of the user running Blender.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4470


Solution: 
    All Blender users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/blender-2.40"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-08] Blender: Heap-based buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Blender: Heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/blender", unaffected: make_list("ge 2.40"), vulnerable: make_list("lt 2.40")
)) { security_warning(0); exit(0); }
