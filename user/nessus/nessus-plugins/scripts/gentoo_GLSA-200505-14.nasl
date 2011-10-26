# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18338);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-14
(Cheetah: Untrusted module search path)


    Brian Bird discovered that Cheetah searches for modules in the
    world-writable /tmp directory.
  
Impact

    A malicious local user could place a module containing arbitrary
    code in /tmp, which when imported would run with escalated privileges.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://secunia.com/advisories/15386/


Solution: 
    All Cheetah users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-python/cheetah-0.9.17-rc1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-14] Cheetah: Untrusted module search path");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cheetah: Untrusted module search path');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-python/cheetah", unaffected: make_list("ge 0.9.17-rc1"), vulnerable: make_list("lt 0.9.17-rc1")
)) { security_warning(0); exit(0); }
