#
# This script was written by Renaud Deraison
#
# It simply puts the content of cgibin() in the KB.
#

if(description)
{
 script_id(10308);
 script_version ("$Revision: 1.2 $");

 name["english"] = "cgibin() in the KB";

 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin puts the content of cgibin() in the KB so that
the function cgi_dirs() can work properly";



 script_description(english:desc["english"]);
 
 summary["english"] = "cgibin() in kb";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Settings";
 family["francais"] = "Configuration";
 script_family(english:family["english"], francais:family["francais"]);
 
 
 exit(0);
}



dir = cgibin();
cgis = split(dir, sep:":", keep:FALSE);
foreach dir (cgis)
{
 set_kb_item(name:"/tmp/cgibin", value:dir);
}
exit(0);
