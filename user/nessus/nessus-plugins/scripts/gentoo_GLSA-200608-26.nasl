# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22288);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-26");
 script_cve_id("CVE-2006-4330", "CVE-2006-4331", "CVE-2006-4332", "CVE-2006-4333");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-26
(Wireshark: Multiple vulnerabilities)


    The following vulnerabilities have been discovered in Wireshark.
    Firstly, if the IPsec ESP parser is used it is susceptible to
    off-by-one errors, this parser is disabled by default; secondly, the
    SCSI dissector is vulnerable to an unspecified crash; and finally, the
    Q.2931 dissector of the SSCOP payload may use all the available memory
    if a port range is configured. By default, no port ranges are
    configured.
  
Impact

    An attacker might be able to exploit these vulnerabilities, resulting
    in a crash or the execution of arbitrary code with the permissions of
    the user running Wireshark, possibly the root user.
  
Workaround

    Disable the SCSI and Q.2931 dissectors with the "Analyse" and "Enabled
    protocols" menus. Make sure the ESP decryption is disabled, with the
    "Edit -> Preferences -> Protocols -> ESP" menu.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4330
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4331
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4332
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4333
    http://www.wireshark.org/security/wnpa-sec-2006-02.html


Solution: 
    All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/wireshark-0.99.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-26] Wireshark: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wireshark: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/wireshark", unaffected: make_list("ge 0.99.3"), vulnerable: make_list("lt 0.99.3")
)) { security_warning(0); exit(0); }
