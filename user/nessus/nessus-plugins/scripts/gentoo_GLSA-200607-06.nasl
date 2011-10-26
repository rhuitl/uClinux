# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22080);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200607-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200607-06
(libpng: Buffer overflow)


    In pngrutil.c, the function png_decompress_chunk() allocates
    insufficient space for an error message, potentially overwriting stack
    data, leading to a buffer overflow.
  
Impact

    By enticing a user to load a maliciously crafted PNG image, an attacker
    could execute arbitrary code with the rights of the user, or crash the
    application using the libpng library, such as the
    emul-linux-x86-baselibs.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://heanet.dl.sourceforge.net/sourceforge/libpng/libpng-1.2.12-README.txt
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3334


Solution: 
    All libpng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libpng-1.2.12"
    All AMD64 emul-linux-x86-baselibs users should also upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-baselibs-2.5.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200607-06] libpng: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libpng: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-emulation/emul-linux-x86-baselibs", arch: "amd64", unaffected: make_list("ge 2.5.1"), vulnerable: make_list("lt 2.5.1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-libs/libpng", unaffected: make_list("ge 1.2.12"), vulnerable: make_list("lt 1.2.12")
)) { security_warning(0); exit(0); }
