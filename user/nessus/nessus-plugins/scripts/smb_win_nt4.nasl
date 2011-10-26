#
# (C) Tenable Network Security
#

if(description)
{
  script_id(19699);
  script_version("$Revision: 1.4 $");

  name["english"] = "Unsupported Windows NT 4.0 Installation";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running a version of Microsoft Windows NT 4.0.

This operating system is no longer supported by Microsoft, therefore this system 
is vulnerable to multiple remotely exploitable vulnerabilities which may allow an
attacker or a worm to take the complete control of the remote system 
(MS05-027, MS05-043 ...).

Solution : Upgrade to Windows XP/2000/2003.
See also : http://www.microsoft.com/ntserver/ProductInfo/Availability/Retiring.asp
Note : Nessus disabled tests for unpatched/unsupported flaws against this system. 
Risk factor : High";


  script_description(english:desc["english"]);

  summary["english"] = "Remote Host is running Windows NT 4.0";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "Windows";
  script_family(english:family["english"]);

  script_dependencie("os_fingerprint.nasl","smb_nativelanman.nasl");
  exit (0);
}

nt4 = 0;

os = get_kb_item("Host/OS/icmp");
if ( os && "Windows NT 4.0" >< os )
  nt4++;

os = get_kb_item ("Host/OS/smb") ;
if ( os && "Windows 4.0" >< os )
  nt4++;

if (nt4 != 0)
  security_hole (0);

