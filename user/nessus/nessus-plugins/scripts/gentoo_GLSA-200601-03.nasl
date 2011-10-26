# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20413);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-03");
 script_cve_id("CVE-2005-3538", "CVE-2005-3539");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-03
(HylaFAX: Multiple vulnerabilities)


    Patrice Fournier discovered that HylaFAX runs the notify script on
    untrusted user input. Furthermore, users can log in without a password
    when HylaFAX is installed with the pam USE-flag disabled.
  
Impact

    An attacker could exploit the input validation vulnerability to
    run arbitrary code as the user running HylaFAX, which is usually uucp.
    The password vulnerability could be exploited to log in without proper
    user credentials.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3538
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3539
    http://www.hylafax.org/content/HylaFAX_4.2.4_release


Solution: 
    All HylaFAX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/hylafax-4.2.3-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-03] HylaFAX: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'HylaFAX: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/hylafax", unaffected: make_list("ge 4.2.3-r1"), vulnerable: make_list("lt 4.2.3-r1")
)) { security_hole(0); exit(0); }
