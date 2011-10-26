# 
# (C) Tenable Network Security
#
# Credit:
# From: Joe Stewart <jstewart@lurhq.com>
# To: TH-Research
# Subject: [TH-research] Bagle remote uninstall
# Date: Tue, 20 Jan 2004 17:19:41 -0500
#

if(description)
{
 script_id(12027);

 script_version("$Revision: 1.9 $");

 name["english"] = "Bagle remover";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host had the bagle virus installed. Nessus probably 
removed it by connecting to port 6777 of this host and use the 
built-in removal command of this virus to clean up the remote host,
however you should make sure that :
- The virus was indeed properly removed
- The remote computer has not be altered in any other way.

Solution: Re-install this system from scratch if the virus backdoor has been
used by an intruder
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Removes bagle if it is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_require_ports(6777);
 exit(0);
}

if ( ! get_port_state(6777) ) 
	exit(0);


soc = open_sock_tcp(6777);
if ( soc )
{
 send(socket:soc, data:raw_string(0x43, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x04) + "12" + raw_string(0));
 r = recv(socket:soc, length:4096);
 display(hexstr(r), "\n");
 if ( hexstr(r) == "01000000791a0000" ) security_hole(6777);
 close(soc);
}

