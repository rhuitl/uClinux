# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18383);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200505-19");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-19
(gxine: Format string vulnerability)


    Exworm discovered that gxine insecurely implements formatted
    printing in the hostname decoding function.
  
Impact

    A remote attacker could entice a user to open a carefully crafted
    file with gxine, possibly leading to the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1692
    http://www.securityfocus.com/bid/13707
    http://www.0xbadexworm.org/adv/gxinefmt.txt


Solution: 
    All gxine users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-video/gxine
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-19] gxine: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gxine: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/gxine", unaffected: make_list("rge 0.3.3-r2", "rge 0.4.1-r1", "ge 0.4.4"), vulnerable: make_list("lt 0.4.4")
)) { security_warning(0); exit(0); }
