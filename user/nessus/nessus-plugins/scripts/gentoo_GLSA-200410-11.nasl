# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15472);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200410-11");
 script_cve_id("CVE-2004-0803");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-11
(tiff: Buffer overflows in image decoding)


    Chris Evans found heap-based overflows in RLE decoding routines in
    tif_next.c, tif_thunder.c and potentially tif_luv.c.
  
Impact

    A remote attacker could entice a user to view a carefully crafted TIFF
    image file, which would potentially lead to execution of arbitrary code
    with the rights of the user viewing the image. This affects any program
    that makes use of the tiff library, including GNOME and KDE web browsers or
    mail readers.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0803


Solution: 
    All tiff library users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/tiff-3.6.1-r2"
    # emerge ">=media-libs/tiff-3.6.1-r2"
    xv makes use of the tiff library and needs to be recompiled to receive the
    new patched version of the library. All xv users should also upgrade to the
    latest version:
    # emerge sync
    # emerge -pv ">=media-gfx/xv-3.10a-r8"
    # emerge ">=media-gfx/xv-3.10a-r8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-11] tiff: Buffer overflows in image decoding");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'tiff: Buffer overflows in image decoding');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/xv", unaffected: make_list("ge 3.10a-r8"), vulnerable: make_list("le 3.10a-r7")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-libs/tiff", unaffected: make_list("ge 3.6.1-r2"), vulnerable: make_list("lt 3.6.1-r2")
)) { security_warning(0); exit(0); }
