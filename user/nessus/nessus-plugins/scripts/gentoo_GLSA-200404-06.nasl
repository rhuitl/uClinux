# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14471);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200404-06");
 script_cve_id("CVE-2004-0080");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-06
(Util-linux login may leak sensitive data)


    In some situations the login program could leak sensitive data due to an
    incorrect usage of a reallocated pointer.
	NOTE: Only users who have PAM support disabled on their
	systems (i.e.  -PAM in their USE variable) will be affected by this
	vulnerability.  By default, this USE flag is enabled on all
	architectures.  Users with PAM support on their system receive login binaries
	as part of the pam-login package, which remains unaffected.
  
Impact

    A remote attacker may obtain sensitive data.
  
Workaround

     A workaround is not currently known for this issue. All users are advised to upgrade to the latest version of the affected package.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0080


Solution: 
    All util-linux users should upgrade to version 2.12 or later:
    # emerge sync
	# emerge -pv ">=sys-apps/util-linux-2.12"
    # emerge ">=sys-apps/util-linux-2.12"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-06] Util-linux login may leak sensitive data");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Util-linux login may leak sensitive data');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/util-linux", unaffected: make_list("ge 2.12"), vulnerable: make_list("le 2.11")
)) { security_warning(0); exit(0); }
