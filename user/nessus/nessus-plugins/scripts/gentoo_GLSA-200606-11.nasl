# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21704);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-11");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-11
(JPEG library: Denial of Service)


    Tavis Ormandy of the Gentoo Linux Auditing Team discovered that
    the vulnerable JPEG library ebuilds compile JPEG without the --maxmem
    feature which is not recommended.
  
Impact

    By enticing a user to load a specially crafted JPEG image file an
    attacker could cause a Denial of Service, due to memory exhaustion.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    JPEG users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/jpeg-6b-r7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-11] JPEG library: Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'JPEG library: Denial of Service');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/jpeg", unaffected: make_list("ge 6b-r7"), vulnerable: make_list("lt 6b-r7")
)) { security_warning(0); exit(0); }
