# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22283);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-21");
 script_cve_id("CVE-2006-3083", "CVE-2006-3084");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-21
(Heimdal: Multiple local privilege escalation vulnerabilities)


    The ftpd and rcp applications provided by Heimdal fail to check the
    return value of calls to seteuid().
  
Impact

    A local attacker could exploit this vulnerability to execute arbitrary
    code with elevated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.pdc.kth.se/heimdal/advisory/2006-08-08/
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3083
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3084


Solution: 
    All Heimdal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/heimdal-0.7.2-r3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-21] Heimdal: Multiple local privilege escalation vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Heimdal: Multiple local privilege escalation vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/heimdal", unaffected: make_list("ge 0.7.2-r3"), vulnerable: make_list("lt 0.7.2-r3")
)) { security_hole(0); exit(0); }
