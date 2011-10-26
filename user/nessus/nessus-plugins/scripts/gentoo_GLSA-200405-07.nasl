# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14493);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-07");
 script_cve_id("CVE-2004-0400");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-07
(Exim verify=header_syntax buffer overflow)


    When the option "verify = header_syntax" is used in an ACL in the
    configuration file, Exim is vulnerable to a buffer overflow attack that can
    be triggered remotely by sending malicious headers in an email message.
    Note that this option is not enabled in Exim\'s default configuration file.
  
Impact

    This vulnerability can be exploited to trigger a denial of service attack
    and potentially execute arbitrary code with the rights of the user used by
    the Exim daemon (by default this is the "mail" user in Gentoo Linux).
  
Workaround

    Make sure the verify=header_syntax option is not used in your exim.conf
    file.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0400


Solution: 
    All users of Exim should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-mail/exim-4.33-r1"
    # emerge ">=net-mail/exim-4.33-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-07] Exim verify=header_syntax buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Exim verify=header_syntax buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/exim", unaffected: make_list("ge 4.33-r1"), vulnerable: make_list("le 4.33")
)) { security_hole(0); exit(0); }
