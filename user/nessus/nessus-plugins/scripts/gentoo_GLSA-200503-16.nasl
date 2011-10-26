# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17318);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0008");
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200503-16");
 script_cve_id("CVE-2005-0699", "CVE-2005-0704", "CVE-2005-0705", "CVE-2005-0739");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-16
(Ethereal: Multiple vulnerabilities)


    There are multiple vulnerabilities in versions of Ethereal earlier than
    0.10.10, including:
    The Etheric, 3GPP2 A11 and IAPP dissectors are vulnerable to buffer
    overflows (CVE-2005-0704, CVE-2005-0699 and CVE-2005-0739).
    The GPRS-LLC could crash when the "ignore cipher bit" option is
    enabled (CVE-2005-0705).
    Various vulnerabilities in JXTA and sFlow dissectors.
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal and execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol
    dissectors. However, it is strongly recommended that you upgrade to the
    latest stable version.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0699
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0704
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0705
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0739
    http://www.ethereal.com/appnotes/enpa-sa-00018.html


Solution: 
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.10"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-16] Ethereal: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.10"), vulnerable: make_list("lt 0.10.10")
)) { security_hole(0); exit(0); }
