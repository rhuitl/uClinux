# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22165);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-07");
 script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-07
(libTIFF: Multiple vulnerabilities)


    Tavis Ormandy of the Google Security Team discovered several heap and
    stack buffer overflows and other flaws in libTIFF. The affected parts
    include the TIFFFetchShortPair(), TIFFScanLineSize() and
    EstimateStripByteCounts() functions, and the PixarLog and NeXT RLE
    decoders.
  
Impact

    A remote attacker could entice a user to open a specially crafted TIFF
    file, resulting in the possible execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3459
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3460
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3461
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3462
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3463
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3464
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3465


Solution: 
    All libTIFF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/tiff-3.8.2-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-07] libTIFF: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libTIFF: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/tiff", unaffected: make_list("ge 3.8.2-r2"), vulnerable: make_list("lt 3.8.2-r2")
)) { security_warning(0); exit(0); }
