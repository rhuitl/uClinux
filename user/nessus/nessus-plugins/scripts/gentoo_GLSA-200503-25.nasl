# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-25.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17581);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200503-25");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-25
(OpenSLP: Multiple buffer overflows)


    Multiple buffer overflows have been found in OpenSLP, when
    handling malformed SLP packets.
  
Impact

    By sending specially crafted SLP packets, a remote attacker could
    potentially execute arbitrary code with the rights of the OpenSLP
    daemon.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.novell.com/linux/security/advisories/2005_15_openslp.html


Solution: 
    All OpenSLP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/openslp-1.2.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-25] OpenSLP: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSLP: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-libs/openslp", unaffected: make_list("ge 1.2.1"), vulnerable: make_list("lt 1.2.1")
)) { security_hole(0); exit(0); }
