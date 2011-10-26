# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14746);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-18");
 script_cve_id("CVE-2004-0806");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-18
(cdrtools: Local root vulnerability in cdrecord if set SUID root)


    Max Vozeler discovered that the cdrecord utility, when set to SUID root,
    fails to drop root privileges before executing a user-supplied RSH program.
    By default, Gentoo does not ship the cdrecord utility as SUID root and
    therefore is not vulnerable. However, many users (and CD-burning
    front-ends) set this manually after installation.
  
Impact

    A local attacker could specify a malicious program using the $RSH
    environment variable and have it executed by the SUID cdrecord, resulting
    in root privileges escalation.
  
Workaround

    As a workaround, you could remove the SUID rights from your cdrecord
    utility :
    # chmod a-s /usr/bin/cdrecord
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0806


Solution: 
    All cdrtools users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-cdr/cdrtools-2.01_alpha37-r1"
    # emerge ">=app-cdr/cdrtools-2.01_alpha37-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-18] cdrtools: Local root vulnerability in cdrecord if set SUID root");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cdrtools: Local root vulnerability in cdrecord if set SUID root');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-cdr/cdrtools", unaffected: make_list("ge 2.01_alpha37-r1", "rge 2.01_alpha28-r2"), vulnerable: make_list("le 2.01_alpha37")
)) { security_hole(0); exit(0); }
