# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17250);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-03
(Gaim: Multiple Denial of Service issues)


    Specially crafted SNAC packets sent by other instant-messaging
    users can cause Gaim to loop endlessly (CVE-2005-0472). Malformed HTML
    code could lead to invalid memory accesses (CVE-2005-0208 and
    CVE-2005-0473).
  
Impact

    Remote attackers could exploit these issues, resulting in a Denial
    of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0208
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0472
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0473


Solution: 
    All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gaim-1.1.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-03] Gaim: Multiple Denial of Service issues");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Multiple Denial of Service issues');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4")
)) { security_warning(0); exit(0); }
