# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14538);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200407-05");
 script_cve_id("CVE-2004-0419");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-05
(XFree86, X.org: XDM ignores requestPort setting)


    XDM will open TCP sockets for its chooser, even if the
    DisplayManager.requestPort setting is set to 0. Remote clients can use this
    port to connect to XDM and request a login window, thus allowing access to
    the system.
  
Impact

    Authorized users may be able to login remotely to a machine running XDM,
    even if this option is disabled in XDM\'s configuration. Please note that an
    attacker must have a preexisting account on the machine in order to exploit
    this vulnerability.
  
Workaround

    There is no known workaround at this time. All users should upgrade to the
    latest available version of X.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0419
    http://bugs.xfree86.org/show_bug.cgi?id=1376


Solution: 
    If you are using XFree86, you should run the following:
    # emerge sync
    # emerge -pv ">=x11-base/xfree-4.3.0-r6"
    # emerge ">=x11-base/xfree-4.3.0-r6"
    If you are using X.org\'s X11 server, you should run the following:
    # emerge sync
    # emerge -pv ">=x11-base/xorg-x11-6.7.0-r1"
    # emerge ">=x11-base/xorg-x11-6.7.0-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-05] XFree86, X.org: XDM ignores requestPort setting");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XFree86, X.org: XDM ignores requestPort setting');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-base/xfree", unaffected: make_list("ge 4.3.0-r6"), vulnerable: make_list("le 4.3.0-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("ge 6.7.0-r1"), vulnerable: make_list("le 6.7.0")
)) { security_warning(0); exit(0); }
