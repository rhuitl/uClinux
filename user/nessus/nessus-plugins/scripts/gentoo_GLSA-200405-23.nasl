# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14509);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-23");
 script_cve_id("CVE-2004-0434");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-23
(Heimdal: Kerberos 4 buffer overflow in kadmin)


    A buffer overflow was discovered in kadmind, a server for administrative
    access to the Kerberos database.
  
Impact

    By sending a specially formatted message to kadmind, a remote attacker may
    be able to crash kadmind causing a denial of service, or execute arbitrary
    code with the permissions of the kadmind process.
  
Workaround

    For a temporary workaround, providing you do not require Kerberos 4
    support, you may turn off Kerberos 4 kadmin by running kadmind with the
    --no-kerberos4 option.
  
References:
    http://www.pdc.kth.se/heimdal/advisory/2004-05-06/
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0434


Solution: 
    All Heimdal users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-crypt/heimdal-0.6.2"
    # emerge ">=app-crypt/heimdal-0.6.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-23] Heimdal: Kerberos 4 buffer overflow in kadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Heimdal: Kerberos 4 buffer overflow in kadmin');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/heimdal", unaffected: make_list("ge 0.6.2"), vulnerable: make_list("lt 0.6.2")
)) { security_hole(0); exit(0); }
