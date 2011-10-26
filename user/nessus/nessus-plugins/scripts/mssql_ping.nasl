 desc["english"] = "
Synopsis :

It is possible to determine remote SQL server version

Description :

Microsoft SQL server has a function wherein remote users can
query the database server for the version that is being run.
The query takes place over the same UDP port which handles the
mapping of multiple SQL server instances on the same machine.

CAVEAT: It is important to note that, after Version 8.00.194,
Microsoft decided not to update this function.  This means that
the data returned by the SQL ping is inaccurate for newer releases
of SQL Server.

Solution :

filter incoming traffic to this port

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";



if(description)
{
 script_id(10674);
 script_version ("$Revision: 1.19 $");
 name["english"] = "Microsoft's SQL UDP Info Query";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Microsoft's SQL UDP Info Query";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 H D Moore");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#

##
# data returned will look like:
#
#   xServerName;REDEMPTION;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np;\\REDEMPTION\pipe\sql\query;;
#
##

# this magic info request packet
req = raw_string(0x02);


if(!get_udp_port_state(1434))exit(0);

soc = open_sock_udp(1434);


if(soc)
{
	send(socket:soc, data:req);
	r  = recv(socket:soc, length:4096);
	close(soc);
	if(!r)exit(0);
	set_kb_item(name:"MSSQL/UDP/Ping", value:TRUE);
        r = strstr(r, "Server");
        r = str_replace(find:";", replace:" ", string:r);
	if(r)
	{
 		report += string("Nessus sent an MS SQL 'ping' request. The results were : \n", r, "\n\n");
                report += string("If you are not running multiple instances of Microsoft SQL Server\n");
                report += string("on the same machine, It is suggested you filter incoming traffic to this port");

		 report = string (desc["english"],
				"\n\nPlugin output :\n\n",
				report);

		security_note(port:1434, protocol:"udp", data:report);
		set_kb_item(name:"mssql/udp/1434", value:TRUE);
	}
}
