# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21317);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-02");
 script_cve_id("CVE-2006-1526");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-02
(X.Org: Buffer overflow in XRender extension)


    X.Org miscalculates the size of a buffer in the XRender extension.
  
Impact

    An X.Org user could exploit this issue to make the X server
    execute arbitrary code with elevated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1526


Solution: 
    All X.Org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-x11-6.8.2-r7"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-02] X.Org: Buffer overflow in XRender extension");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.Org: Buffer overflow in XRender extension');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("ge 6.8.2-r7"), vulnerable: make_list("lt 6.8.2-r7")
)) { security_hole(0); exit(0); }
