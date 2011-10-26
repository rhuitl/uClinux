
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 
 script_id(10483);  
 script_version ("$Revision: 1.11 $");

 name["english"] = "Unpassworded PostgreSQL";
 name["francais"] = "PostgreSQL sans mot de passe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script attempts to log into to the remote
PostgreSQL daemon, and retrieves the list of the
databases installed on the remote host.

Risk factor : High";

	
 desc["francais"] = "
Ce script tente de se logguer dans le daemon PostgreSQL distant
et d'en obtenir la liste des bases qu'il gère.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to log into the remote PostgreSQL daemon";
 summary["francais"] = "Tente de se logger dans le daemon PostgreSQL distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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
    req = raw_string(0x51) + "select * from pg_database;" + 
    	  raw_string(0x00);
    send(socket:soc, data:req);
    
    r = recv(socket:soc, length:65535);
    #display(r);
    close(soc);
    skip = 87;
    ok = 1;
    while(ok)
    {
     db = "";
 
     len = ord(r[skip]);
     len_r = strlen(r);
     lenskip = len + skip;
  
     if(lenskip > len_r)ok = 0;
     else
     {
      len = ord(r[skip]) - 4;
      for(i=0;i<len;i=i+1)
       db = db + r[skip+i+1];
    
      dbs = dbs + ". " + db + string("\n");
      skip = skip + len + 21 + len;
      if(skip > strlen(r))ok=0;
     }
   }
    
    report = string(
"Your PostgreSQL database is not password protected.\n",
"We could log in as the user '", usr, "'.\n\n",
"Anyone can connect to it and do whatever he wants to your data\n",
"(deleting a database, adding bogus entries, ...)\n\n",
"Here is the list of the databases that are present on the remote host : \n\n",
dbs, "\n",
"Solution : Log into this host, and set a password for this user (if not\n",
"done already) - using the command ALTER USER (see the documentation on\n",
"www.postgresql.org).\n",
"In addition to this, configure the file pg_hba.conf to require a password\n",
"(or kerberos) authentication for all the remote hosts that have\n",
"legitimate access to this database.\n",
"You should also require a password locally, by adding the line\n",
"'local all password' in this file.\n\n",
"Risk factor : High");
  security_hole(port:port, data:report);
  exit(0);
  }
  close(soc);
}
