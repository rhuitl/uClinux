# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22010);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200607-03");
 script_cve_id("CVE-2006-2193", "CVE-2006-2656");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200607-03
(libTIFF: Multiple buffer overflows)


    A buffer overflow has been found in the t2p_write_pdf_string function
    in tiff2pdf, which can been triggered with a TIFF file containing a
    DocumentName tag with UTF-8 characters. An additional buffer overflow
    has been found in the handling of the parameters in tiffsplit.
  
Impact

    A remote attacker could entice a user to load a specially crafted TIFF
    file, resulting in the possible execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2193
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2656


Solution: 
    All libTIFF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/tiff-3.8.2-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200607-03] libTIFF: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libTIFF: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/tiff", unaffected: make_list("ge 3.8.2-r1"), vulnerable: make_list("lt 3.8.2-r1")
)) { security_warning(0); exit(0); }
