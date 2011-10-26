# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-25.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22287);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-25");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-25
(X.org and some X.org libraries: Local privilege escalations)


    Several X.org libraries and X.org itself contain system calls to
    set*uid() functions, without checking their result.
  
Impact

    Local users could deliberately exceed their assigned resource limits
    and elevate their privileges after an unsuccessful set*uid() system
    call. This requires resource limits to be enabled on the machine.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://lists.freedesktop.org/archives/xorg/2006-June/016146.html


Solution: 
    All X.Org xdm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-apps/xdm-1.0.4-r1"
    All X.Org xinit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-apps/xinit-1.0.2-r6"
    All X.Org xload users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-apps/xload-1.0.1-r1"
    All X.Org xf86dga users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-apps/xf86dga-1.0.1-r1"
    All X.Org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-x11-6.9.0-r2"
    All X.Org X servers users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-server-1.1.0-r1"
    All X.Org X11 library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/libX11-1.0.1-r1"
    All X.Org xtrans library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/xtrans-1.0.1-r1"
    All xterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/xterm-215"
    All users of the X11R6 libraries for emulation of 32bit x86 on amd64
    should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-xlibs-7.0-r2"
    Please note that the fixed packages have been available for most
    architectures since June 30th but the GLSA release was held up waiting
    for the remaining architectures.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-25] X.org and some X.org libraries: Local privilege escalations");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.org and some X.org libraries: Local privilege escalations');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-apps/xf86dga", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-apps/xinit", unaffected: make_list("ge 1.0.2-r6"), vulnerable: make_list("lt 1.0.2-r6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-base/xorg-server", unaffected: make_list("rge 1.0.2-r6", "ge 1.1.0-r1"), vulnerable: make_list("lt 1.1.0-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("rge 6.8.2-r8", "ge 6.9.0-r2"), vulnerable: make_list("lt 6.9.0-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-emulation/emul-linux-x86-xlibs", arch: "amd64", unaffected: make_list("ge 7.0-r2"), vulnerable: make_list("lt 7.0-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-libs/xtrans", unaffected: make_list("ge 1.0.0-r1"), vulnerable: make_list("lt 1.0.0-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-libs/libX11", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-terms/xterm", unaffected: make_list("ge 215"), vulnerable: make_list("lt 215")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-apps/xload", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-apps/xdm", unaffected: make_list("ge 1.0.4-r1"), vulnerable: make_list("lt 1.0.4-r1")
)) { security_hole(0); exit(0); }
