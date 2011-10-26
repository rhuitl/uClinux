#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Trustix security engineers
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 
 script_id(15417);  
 script_cve_id("CVE-2004-0977");
 script_bugtraq_id(11295);
 script_version ("$Revision: 1.4 $");

 name["english"] = "PostgreSQL insecure temporary file creation";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote PostgreSQL server, according to its version number, is vulnerable 
to an unspecified insecure temporary file creation flaw, which may allow 
a local attacker to overwrite arbitrary files with the privileges of 
the application.

Solution : Upgrade to newer version of this software.
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log into the remote PostgreSQL daemon";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
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
     if(ereg(string:r, pattern:"PostgreSQL ([0-6]\.|7\.(4\.[0-5])|([0-3]\..*)).*")){
     	security_warning(port);
	exit(0);
	}
     }
    exit(0);
   }
}
