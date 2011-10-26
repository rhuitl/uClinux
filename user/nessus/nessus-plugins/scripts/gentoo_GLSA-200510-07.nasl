# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19977);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200510-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-07
(RealPlayer, Helix Player: Format string vulnerability)


     "c0ntex" reported that RealPlayer and Helix Player suffer from a
    heap overflow.
  
Impact

    By enticing a user to play a specially crafted realpix (.rp) or
    realtext (.rt) file, an attacker could execute arbitrary code with the
    permissions of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2710


Solution: 
    All RealPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/realplayer-10.0.6"
    All Helix Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/helixplayer-1.0.6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-07] RealPlayer, Helix Player: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RealPlayer, Helix Player: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/helixplayer", unaffected: make_list("ge 1.0.6"), vulnerable: make_list("lt 1.0.6")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-video/realplayer", unaffected: make_list("ge 10.0.6"), vulnerable: make_list("lt 10.0.6")
)) { security_warning(0); exit(0); }
