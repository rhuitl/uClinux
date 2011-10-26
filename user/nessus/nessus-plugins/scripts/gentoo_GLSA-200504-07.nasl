# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18001);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-07");
 script_cve_id("CVE-2005-0706");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-07
(GnomeVFS, libcdaudio: CDDB response overflow)


    Joseph VanAndel has discovered a buffer overflow in Grip when
    processing large CDDB results (see GLSA 200503-21). The same overflow
    is present in GnomeVFS and libcdaudio code.
  
Impact

    A malicious CDDB server could cause applications making use of GnomeVFS
    or libcdaudio libraries to crash, potentially allowing the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0706
    http://www.gentoo.org/security/en/glsa/glsa-200503-21.xml


Solution: 
    All GnomeVFS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose gnome-base/gnome-vfs
    All libcdaudio users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libcdaudio-0.99.10-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-07] GnomeVFS, libcdaudio: CDDB response overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnomeVFS, libcdaudio: CDDB response overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/libcdaudio", unaffected: make_list("ge 0.99.10-r1"), vulnerable: make_list("lt 0.99.10-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "gnome-base/gnome-vfs", unaffected: make_list("ge 2.8.4-r1", "rge 1.0.5-r4"), vulnerable: make_list("lt 2.8.4-r1")
)) { security_warning(0); exit(0); }
