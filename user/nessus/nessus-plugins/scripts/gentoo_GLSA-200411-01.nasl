# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2004 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15589);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200411-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-01
(ppp: Remote denial of service vulnerability)


    The pppd server improperly verifies header fields, making it vulnerable to
    denial of service attacks.
  
Impact

    An attacker can cause the pppd server to access memory that it isn\'t
    allowed to, causing the server to crash. No code execution is possible with
    this vulnerability, because no data is getting copied.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/379450


Solution: 
    All ppp users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dialup/ppp-2.4.2-r7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2004 Michel Arboi");
 script_name(english: "[GLSA-200411-01] ppp: Remote denial of service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ppp: Remote denial of service vulnerability');
 exit(0);
}

exit(0); # Gentoo now claims it's not an issue
include('qpkg.inc');
if (qpkg_check(package: "net-dialup/ppp", unaffected: make_list("ge 2.4.2-r7"), vulnerable: make_list("lt 2.4.2-r7")
)) { security_warning(0); exit(0); }
