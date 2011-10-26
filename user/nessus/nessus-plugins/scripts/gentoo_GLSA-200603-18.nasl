# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21125);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-18
(Pngcrush: Buffer overflow)


    Carsten Lohrke of Gentoo Linux reported that Pngcrush contains a
    vulnerable version of zlib (GLSA 200507-19).
  
Impact

    By creating a specially crafted data stream, attackers can
    overwrite data structures for applications that use Pngcrush, resulting
    in a Denial of Service and potentially arbitrary code execution.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.gentoo.org/security/en/glsa/glsa-200507-19.xml
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1849


Solution: 
    All Pngcrush users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/pngcrush-1.6.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-18] Pngcrush: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pngcrush: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/pngcrush", unaffected: make_list("ge 1.6.2"), vulnerable: make_list("lt 1.6.2")
)) { security_warning(0); exit(0); }
