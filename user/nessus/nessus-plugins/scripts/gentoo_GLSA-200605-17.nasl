# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21615);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-17
(libTIFF: Multiple vulnerabilities)


    Multiple vulnerabilities, ranging from integer overflows and NULL
    pointer dereferences to double frees, were reported in libTIFF.
  
Impact

    An attacker could exploit these vulnerabilities by enticing a user
    to open a specially crafted TIFF image, possibly leading to the
    execution of arbitrary code or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0405
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2024
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2025
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2026


Solution: 
    All libTIFF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/tiff-3.8.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-17] libTIFF: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libTIFF: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/tiff", unaffected: make_list("ge 3.8.1"), vulnerable: make_list("lt 3.8.1")
)) { security_warning(0); exit(0); }
