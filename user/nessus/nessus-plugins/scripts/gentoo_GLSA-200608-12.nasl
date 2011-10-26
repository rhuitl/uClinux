# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22171);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-12");
 script_cve_id("CVE-2006-2450");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-12
(x11vnc: Authentication bypass in included LibVNCServer code)


    x11vnc includes vulnerable LibVNCServer code, which fails to properly
    validate protocol types effectively letting users decide what protocol
    to use, such as "Type 1 - None" (GLSA-200608-05). x11vnc will accept
    this security type, even if it is not offered by the server.
  
Impact

    An attacker could exploit this vulnerability to gain unauthorized
    access with the privileges of the user running the VNC server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2450
    http://www.gentoo.org/security/en/glsa/glsa-200608-05.xml


Solution: 
    All x11vnc users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-misc/x11vnc-0.8.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-12] x11vnc: Authentication bypass in included LibVNCServer code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'x11vnc: Authentication bypass in included LibVNCServer code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-misc/x11vnc", unaffected: make_list("ge 0.8.1"), vulnerable: make_list("lt 0.8.1")
)) { security_hole(0); exit(0); }
