#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The remote host is running an Antivirus.

Description :

The remote host is running Symantec Antivirus Agent, a 
real time embedded service used by Symantec SAVCE and Client
Security.

Risk factor :

None";


if (description)
{
 script_id(22419);
 script_version("$Revision: 1.1 $");

 script_name(english:"Symantec SAVCE/Client Security service detection");
 script_summary(english:"Checks for Symantec SAVCE/Client Security service");
 
 script_description(english:desc["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

 script_dependencies("find_service2.nasl");
 script_require_ports(2967);

 exit(0);
}


include ("misc_func.inc");

port = 2967;

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

req = '\x01\x10\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ;
rep = '\x01\x10\x00\x00\x14\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' ;

send (socket:soc, data:req);
buf = recv (socket:soc, length:strlen(rep));

if (buf == rep)
{
 register_service(port: port, proto: "savce");
 security_note (port);
}

