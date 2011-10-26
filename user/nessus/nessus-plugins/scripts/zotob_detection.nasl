#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19429);
 script_version("$Revision: 1.1 $");
 name["english"] = "The remote host is infected by the Zotob Worm";
 script_name(english:name["english"]);
 
 desc["english"] = "
A Microsoft Windows shell is running on port 8888. This may indicate an 
infection by the Zotob worm, although other worms may also create a shell
on this port.

The remote host has been compromised.

Solution : Reinstall the remote host
See also : http://securityresponse.symantec.com/avcenter/venc/data/w32.zotob.a.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Connects to port 8888";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

 family["english"] = "Backdoors";

 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#

port = 8888;
if ( get_port_state(port) )
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 buffer = recv(socket:soc, length:4096);
 if ( "Microsoft Windows" >< buffer &&
     "(C) Copyright 1985-" >< buffer &&
     egrep(pattern:"^[A-Z]:.*>", string:buffer) ) security_hole(port);
}
