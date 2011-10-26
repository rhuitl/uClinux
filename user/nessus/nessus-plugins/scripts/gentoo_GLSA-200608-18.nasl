# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22217);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-18");
 script_cve_id("CVE-2005-1127");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-18
(Net::Server: Format string vulnerability)


    The log function of Net::Server does not handle format string
    specifiers properly before they are sent to syslog.
  
Impact

    By sending a specially crafted datastream to an application using
    Net::Server, an attacker could cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1127


Solution: 
    All Net::Server should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-perl/net-server-0.88"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-18] Net::Server: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Net::Server: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-perl/net-server", unaffected: make_list("ge 0.88"), vulnerable: make_list("lt 0.88")
)) { security_warning(0); exit(0); }
