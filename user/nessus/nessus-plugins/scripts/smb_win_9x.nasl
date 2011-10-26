#
# (C) Tenable Network Security
#
#
# Thanks to Keith Yong for suggesting this

if(description)
{
  script_id(21626);
  script_version("$Revision: 1.3 $");

  name["english"] = "Unsupported Windows 95/98/ME Installation";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote host is running a version of Microsoft Windows which is not 
supported by Microsoft any more.

Description :


The remote host is running a version of Microsoft Windows 9x (95, 98 or ME).
Windows 95 support ended on December 31st, 2001 and Windows 98/ME ended
on July 11th 2006.

A lack of support implies that no new security patches will be released for
this operating system.

Solution : 

Upgrade to Windows XP or newer

See also : 

http://support.microsoft.com/gp/lifean18

Risk factor : 

High";


  script_description(english:desc["english"]);

  summary["english"] = "Remote Host is running Windows 95/98/ME";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  family["english"] = "Windows";
  script_family(english:family["english"]);

  script_dependencie("os_fingerprint.nasl","smb_nativelanman.nasl");
  exit (0);
}

os = get_kb_item("Host/OS/icmp");
if ( os && ereg(pattern:"Windows (95|98|ME)", string:os) )
  security_hole(0);

