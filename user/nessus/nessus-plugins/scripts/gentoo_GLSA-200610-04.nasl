# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22890);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-04");
 script_cve_id("CVE-2006-4253", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-04
(Seamonkey: Multiple vulnerabilities)


    A number of vulnerabilities have been found and fixed in Seamonkey. For
    details please consult the references below.
  
Impact

    The most severe vulnerability involves enticing a user to visit a
    malicious website, crashing the application and executing arbitrary
    code with the rights of the user running Seamonkey.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4253
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4565
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4566
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4568
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4570
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4571


Solution: 
    All Seamonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-1.0.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-04] Seamonkey: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Seamonkey: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/seamonkey", unaffected: make_list("ge 1.0.5"), vulnerable: make_list("lt 1.0.5")
)) { security_warning(0); exit(0); }
