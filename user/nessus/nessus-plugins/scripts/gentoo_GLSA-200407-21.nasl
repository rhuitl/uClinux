# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14554);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200407-21");
 script_cve_id("CVE-2004-0600", "CVE-2004-0686");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-21
(Samba: Multiple buffer overflows)


    Evgeny Demidov found a buffer overflow in SWAT, located in the base64 data
    decoder used to handle HTTP basic authentication (CVE-2004-0600). The same
    flaw is present in the code used to handle the sambaMungedDial attribute
    value, when using the ldapsam passdb backend. Another buffer overflow was
    found in the code used to support the \'mangling method = hash\' smb.conf
    option (CVE-2004-0686). Note that the default Samba value for this option
    is \'mangling method = hash2\' which is not vulnerable.
  
Impact

    The SWAT authentication overflow could be exploited to execute arbitrary
    code with the rights of the Samba daemon process. The overflow in the
    sambaMungedDial handling code is not thought to be exploitable. The buffer
    overflow in \'mangling method = hash\' code could also be used to execute
    arbitrary code on vulnerable configurations.
  
Workaround

    Users disabling SWAT, not using ldapsam passdb backends and not using the
    \'mangling method = hash\' option are not vulnerable.
  
References:
    http://www.samba.org/samba/whatsnew/samba-3.0.5.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0600
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0686


Solution: 
    All Samba users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-fs/samba-3.0.5"
    # emerge ">=net-fs/samba-3.0.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-21] Samba: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.5"), vulnerable: make_list("le 3.0.4-r1")
)) { security_hole(0); exit(0); }
