#
# (C) Tenable
#

if(description)
{
 script_id(22481);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Do not scan fragile devices";
 desc["english"] = "

This script creates a user interface in the 'Prefs' section of the
client letting users enable or disable certain categories of 
network devices and hosts from being scanned.

- Network printers : It is usually a good idea to avoid scanning a
network printer. Scanning a network printer is likely to cause it
to print random data, thus wasting paper and harming the environment ;

- Novell Netware : Older versions of Novell Netware do not withstand
a vulnerability scan. Please read :

http://support.novell.com/cgi-bin/search/searchtid.cgi?/2972443.htm

before doing a vulnerability scan against a Novell server.

";




 script_description(english:desc["english"]);
 script_name(english:name["english"]);
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 summary["english"] = "Define which type of hosts can or can not be scanned";
 script_summary(english:summary["english"]);
 script_copyright(english:"Copyright (C) 2006 Tenable");
 script_category(ACT_INIT);
 script_add_preference(name:"Scan Network Printers", type:"checkbox", value:"no");
 script_add_preference(name:"Scan Novell Netware hosts", type:"checkbox", value:"no");
 exit(0);
}

opt = script_get_preference("Scan Network Printers");
if ( opt )
{
 if ( "yes" >< opt ) set_kb_item(name:"Scan/Do_Scan_Printers", value:TRUE);
}
else if ( safe_checks() == 0 ) set_kb_item(name:"Scan/Do_Scan_Printers", value:TRUE);


opt = script_get_preference("Scan Novell Netware hosts");
if ( opt )
{
 if ( "yes" >< opt ) set_kb_item(name:"Scan/Do_Scan_Novell", value:TRUE);
}
else if ( safe_checks() == 0 ) set_kb_item(name:"Scan/Do_Scan_Novell", value:TRUE);
