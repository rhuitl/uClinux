# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14498);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-12");
 script_cve_id("CVE-2004-0396");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-12
(CVS heap overflow vulnerability)


    Stefan Esser discovered a heap overflow in the CVS server, which can be
    triggered by sending malicious "Entry" lines and manipulating the flags
    related to that Entry. This vulnerability was proven to be exploitable.
  
Impact

    A remote attacker can execute arbitrary code on the CVS server, with the
    rights of the CVS server. By default, Gentoo uses the "cvs" user to run the
    CVS server. In particular, this flaw allows a complete compromise of CVS
    source repositories. If you\'re not running a server, then you are not
    vulnerable.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of CVS.
  
References:
    http://security.e-matters.de/advisories/072004.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0396


Solution: 
    All users running a CVS server should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=dev-util/cvs-1.11.16"
    # emerge ">=dev-util/cvs-1.11.16"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-12] CVS heap overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CVS heap overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/cvs", unaffected: make_list("ge 1.11.16"), vulnerable: make_list("le 1.11.15")
)) { security_hole(0); exit(0); }
