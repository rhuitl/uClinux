# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14564);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-08
(Cfengine: RSA Authentication Heap Corruption)


    Two vulnerabilities have been found in cfservd. One is a buffer overflow in
    the AuthenticationDialogue function and the other is a failure to check the
    proper return value of the ReceiveTransaction function.
  
Impact

    An attacker could use the buffer overflow to execute arbitrary code with
    the permissions of the user running cfservd, which is usually the root
    user. However, before such an attack could be mounted, the IP-based ACL
    would have to be bypassed. With the second vulnerability, an attacker could
    cause a denial of service attack.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Cfengine. (It should be noted
    that disabling cfservd will work around this particular problem. However,
    in many cases, doing so will cripple your Cfengine setup. Upgrading is
    strongly recommended.)
  
References:
    http://www.coresecurity.com/common/showdoc.php?idx=387&idxseccion=10


Solution: 
    All Cfengine users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-misc/cfengine-2.1.8"
    # emerge ">=net-misc/cfengine-2.1.8"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-08] Cfengine: RSA Authentication Heap Corruption");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cfengine: RSA Authentication Heap Corruption');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/cfengine", unaffected: make_list("ge 2.1.8", "lt 2.0.0"), vulnerable: make_list("le 2.1.7")
)) { security_hole(0); exit(0); }
