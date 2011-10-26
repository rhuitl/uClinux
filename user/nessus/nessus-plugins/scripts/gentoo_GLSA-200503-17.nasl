# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17319);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-17");
 script_cve_id("CVE-2005-0664");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-17
(libexif: Buffer overflow vulnerability)


    libexif contains a buffer overflow vulnerability in the EXIF tag
    validation code. When opening an image with a specially crafted EXIF
    tag, the lack of validation can cause applications linked to libexif to
    crash.
  
Impact

    A specially crafted EXIF file could crash applications making use
    of libexif, potentially allowing the execution of arbitrary code with
    the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0664


Solution: 
    All libexif users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libexif-0.5.12-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-17] libexif: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libexif: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/libexif", unaffected: make_list("ge 0.5.12-r1"), vulnerable: make_list("lt 0.5.12-r1")
)) { security_warning(0); exit(0); }
