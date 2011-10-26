#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16309);  
 script_bugtraq_id(12417, 12411);
 script_version ("$Revision: 1.3 $");

 name["english"] = "PostgreSQL multiple flaws (2)";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote PostgreSQL server, according to its version number,
is vulnerable to various flaws which may allow an attacker who
has the rights to query the remote database to obtain a 
shell on this host.

Solution : Upgrade to postgresql 7.2.7, 7.3.9, 7.4.7, 8.0.1 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log into the remote PostgreSQL daemon";
 summary["francais"] = "Tente de se logger dans le daemon PostgreSQL distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/postgres", 5432);
 exit(0);
}


port = get_kb_item("Services/postgres");
if(!port)port = 5432;

if(!get_port_state(port))exit(0);

#
# Request the database 'template1' as the user 'postgres' or 'pgsql'
# 
zero = raw_string(0x00);

user[0] = "postgres";
user[1] = "pgsql";

for(i=0;i<2;i=i+1)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 usr = user[i];
 len = 224 - strlen(usr);

 req = raw_string(0x00, 0x00, 0x01, 0x28, 0x00, 0x02,
    	         0x00, 0x00, 0x74, 0x65, 0x6D, 0x70, 0x6C, 0x61,
		 0x74, 0x65, 0x31) + crap(data:zero, length:55) +
        usr +
       crap(data:zero, length:len);

 send(socket:soc, data:req);
 r = recv(socket:soc, length:5);
 r2 = recv(socket:soc, length:1024);
 if((r[0]=="R") && (strlen(r2) == 10))
  {
    dbs = "";
    req = raw_string(0x51) + "select version();" + 
    	  raw_string(0x00);
    send(socket:soc, data:req);
    
    r = recv(socket:soc, length:65535);
    r = strstr(r, "PostgreSQL");
    if(r != NULL)
     {
      for(i=0;i<strlen(r);i++)
      {
       if(ord(r[i]) == 0)
     	break;
       }
     r = substr(r, 0, i - 1);
     if(ereg(string:r, pattern:"PostgreSQL ([0-6]\.|7\.2\.[0-6][^0-9]|7\.3\.[0-8][^0-9]|7\.4\.[0-6][^0-9]|8\.0\.0[^0-9])")){
     	security_hole(port);
	}
     }
    else if("ERROR: function version()" >< r)security_hole(port);
    exit(0);
   }
}
