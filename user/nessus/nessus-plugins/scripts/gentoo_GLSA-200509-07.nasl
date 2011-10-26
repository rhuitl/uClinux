# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19686);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-07");
 script_cve_id("CVE-2005-2495");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-07
(X.Org: Heap overflow in pixmap allocation)


    X.Org is missing an integer overflow check during pixmap memory
    allocation.
  
Impact

    An X.Org user could exploit this issue to make the X server
    execute arbitrary code with elevated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2495


Solution: 
    All X.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-x11-6.8.2-r3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-07] X.Org: Heap overflow in pixmap allocation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.Org: Heap overflow in pixmap allocation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("ge 6.8.2-r3"), vulnerable: make_list("lt 6.8.2-r3")
)) { security_hole(0); exit(0); }
