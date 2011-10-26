#
# This script was written by Eli Kara <elik@beyondsecurity.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(12639);  
 script_bugtraq_id(10654, 10655);
 script_version ("$Revision: 1.7 $");

 name["english"] = "MySQL Authentication bypass through a zero-length password";
 script_name(english:name["english"]);
 
 desc["english"] = "It is possible to bypass password authentication for a database
 user using a crafted authentication packet with a zero-length password
 
Note: In order to use this script, the MySQL daemon has to allow connection from the
scanning IP address";
 script_description(english:desc["english"]);
 
 summary["english"] = "Log in to MySQL with a zero-length password";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Beyond Security");
 
 family["english"] = "Databases";
 script_family(english:family["english"]);
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

# tested by mysql_unpassworded.nasl
exit (0);
