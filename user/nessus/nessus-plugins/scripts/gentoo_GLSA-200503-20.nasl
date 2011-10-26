# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17345);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-20");
 script_cve_id("CVE-2005-0490");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-20
(curl: NTLM response buffer overflow)


    curl fails to properly check boundaries when handling NTLM
    authentication.
  
Impact

    With a malicious server an attacker could send a carefully crafted
    NTLM response to a connecting client leading to the execution of
    arbitrary code with the permissions of the user running curl.
  
Workaround

    Disable NTLM authentication by not using the --anyauth or --ntlm
    options.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0490


Solution: 
    All curl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/curl-7.13.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-20] curl: NTLM response buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'curl: NTLM response buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/curl", unaffected: make_list("ge 7.13.1"), vulnerable: make_list("lt 7.13.1")
)) { security_warning(0); exit(0); }
