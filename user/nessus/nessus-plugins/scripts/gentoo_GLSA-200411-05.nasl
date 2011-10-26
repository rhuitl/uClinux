# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15610);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200411-05");
 script_cve_id("CVE-2004-0989");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-05
(libxml2: Remotely exploitable buffer overflow)


    Multiple buffer overflows have been detected in the nanoftp and nanohttp
    modules. These modules are responsible for parsing URLs with ftp
    information, and resolving names via DNS.
  
Impact

    An attacker could exploit an application that uses libxml2 by forcing it to
    parse a specially-crafted XML file, potentially causing remote execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/379383
    http://www.xmlsoft.org/ChangeLog.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0989


Solution: 
    All libxml2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/libxml2-2.6.15"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-05] libxml2: Remotely exploitable buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libxml2: Remotely exploitable buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-libs/libxml2", unaffected: make_list("ge 2.6.15"), vulnerable: make_list("lt 2.6.15")
)) { security_hole(0); exit(0); }
