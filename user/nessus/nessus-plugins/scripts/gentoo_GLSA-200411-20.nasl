# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15695);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-20");
 script_cve_id("CVE-2004-0980");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-20
(ez-ipupdate: Format string vulnerability)


    Ulf Harnhammar from the Debian Security Audit Project discovered a format string vulnerability in ez-ipupdate.
  
Impact

    An attacker could exploit this to execute arbitrary code with the permissions of the user running ez-ipupdate, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0980
    http://lists.netsys.com/pipermail/full-disclosure/2004-November/028590.html


Solution: 
    All ez-ipupdate users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/ez-ipupdate-3.0.11_beta8-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-20] ez-ipupdate: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ez-ipupdate: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-dns/ez-ipupdate", unaffected: make_list("ge 3.0.11_beta8-r1"), vulnerable: make_list("le 3.0.11_beta8")
)) { security_hole(0); exit(0); }
