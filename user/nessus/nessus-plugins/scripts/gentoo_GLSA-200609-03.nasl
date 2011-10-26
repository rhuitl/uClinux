# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22325);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-03");
 script_cve_id("CVE-2006-1998", "CVE-2006-1999");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-03
(OpenTTD: Remote Denial of Service)


    OpenTTD is vulnerable to a Denial of Service attack due to a flaw in
    the manner the game server handles errors in command packets.
  
Impact

    An authenticated attacker can cause a Denial of Service by sending an
    invalid error number to a vulnerable OpenTTD server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1998
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1999


Solution: 
    All OpenTTD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-simulation/openttd-0.4.8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-03] OpenTTD: Remote Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenTTD: Remote Denial of Service');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-simulation/openttd", unaffected: make_list("ge 0.4.8"), vulnerable: make_list("lt 0.4.8")
)) { security_warning(0); exit(0); }
