# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200401-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14442);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200401-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200401-02
(Honeyd remote detection vulnerability via a probe packet)


    A bug in handling NMAP fingerprints caused Honeyd to reply to TCP
    packets with both the SYN and RST flags set.  Watching for replies, it is
    possible to detect IP addresses simulated by Honeyd.
  
Impact

    Although there are no public exploits known for Honeyd, the detection
    of Honeyd IP addresses may in some cases be undesirable.
  
Workaround

    Honeyd 0.8 has been released along with an advisory to address this
    issue. In addition, Honeyd 0.8 drops privileges if permitted by the
    configuration file and contains command line flags to force dropping
    of privileges.
  
References:
    http://www.honeyd.org/adv.2004-01.asc


Solution: 
    All users are recommended to update to honeyd version 0.8:
    $> emerge sync
    $> emerge -pv ">=net-analyzer/honeyd-0.8"
    $> emerge ">=net-analyzer/honeyd-0.8"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200401-02] Honeyd remote detection vulnerability via a probe packet");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Honeyd remote detection vulnerability via a probe packet');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/honeyd", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8")
)) { security_warning(0); exit(0); }
