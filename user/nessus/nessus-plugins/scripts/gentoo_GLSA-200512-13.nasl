# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20354);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-13");
 script_cve_id("CVE-2005-4178");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-13
(Dropbear: Privilege escalation)


    Under certain conditions Dropbear could fail to allocate a
    sufficient amount of memory, possibly resulting in a buffer overflow.
  
Impact

    By sending specially crafted data to the server, authenticated
    users could exploit this vulnerability to execute arbitrary code with
    the permissions of the SSH server user, which is the root user by
    default.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4178


Solution: 
    All Dropbear users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/dropbear-0.47"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-13] Dropbear: Privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Dropbear: Privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/dropbear", unaffected: make_list("ge 0.47"), vulnerable: make_list("lt 0.47")
)) { security_hole(0); exit(0); }
