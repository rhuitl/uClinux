# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20355);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-14");
 script_cve_id("CVE-2005-3534");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-14
(NBD Tools: Buffer overflow in NBD server)


    Kurt Fitzner discovered that the NBD server allocates a request
    buffer that fails to take into account the size of the reply header.
  
Impact

    A remote attacker could send a malicious request that can result
    in the execution of arbitrary code with the rights of the NBD server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3534


Solution: 
    All NBD Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-block/nbd-2.8.2-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-14] NBD Tools: Buffer overflow in NBD server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NBD Tools: Buffer overflow in NBD server');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-block/nbd", unaffected: make_list("ge 2.8.2-r1"), vulnerable: make_list("lt 2.8.2-r1")
)) { security_hole(0); exit(0); }
