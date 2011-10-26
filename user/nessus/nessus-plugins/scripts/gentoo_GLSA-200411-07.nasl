# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15612);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-07");
 script_cve_id("CVE-2004-0992");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-07
(Proxytunnel: Format string vulnerability)


    Florian Schilhabel of the Gentoo Linux Security Audit project found a
    format string vulnerability in Proxytunnel. When the program is started in
    daemon mode (-a [port]), it improperly logs invalid proxy answers to
    syslog.
  
Impact

    A malicious remote server could send specially-crafted invalid answers to
    exploit the format string vulnerability, potentially allowing the execution
    of arbitrary code on the tunnelling host with the rights of the Proxytunnel
    process.
  
Workaround

    You can mitigate the issue by only allowing connections to trusted remote
    servers.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0992
    http://proxytunnel.sourceforge.net/news.html


Solution: 
    All Proxytunnel users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/proxytunnel-1.2.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-07] Proxytunnel: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Proxytunnel: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/proxytunnel", unaffected: make_list("ge 1.2.3"), vulnerable: make_list("lt 1.2.3")
)) { security_warning(0); exit(0); }
