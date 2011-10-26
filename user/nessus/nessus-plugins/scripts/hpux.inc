# -*- Fundamental -*-
#
# (C) Tenable Network Security
#
# This script is released under the terms of the Tenable License
#
# hpux.inc 
# $Revision: 1.3 $
#
# @NOGPL@
#


#######################################################
# hpux_check_ctx() returns :                          #
#	1 if system is present in the list            #
#	0 if not                                      #
#######################################################

function hpux_check_ctx (ctx) 
{
 local_var os, hw, list, val, elem;

 os = get_kb_item ("Host/HP-UX/version");
 hw = get_kb_item ("Host/HP-UX/hardware");

 list = split(ctx, sep:' ', keep:0);
 foreach elem (list)
 {
  val = split (elem, sep:":", keep:0);
  if ((val[0] == hw) && (val[1] == os))
    return 1;
 }

 return 0;
}



function hpux_installed (app)
{
 local_var swlist, installed_app;

 swlist = get_kb_item("Host/HP-UX/swlist");

 if ( strlen(app) )
 {
   installed_app = egrep (pattern:string(app,'[\t ]+'), string:swlist);
   if (installed_app)
   {
      return 1;
   }
 }

 return 0;
}



#######################################################
# hpux_patch_installed() returns :                    #
#	1 if one of the patches is installed          #
#	0 if not                                      #
#######################################################

function hpux_patch_installed(patches) 
{
 local_var list, elem, installed_app;
 
 list = split(patches, sep:' ', keep:0);
 foreach elem (list)
 {
  if ( hpux_installed (app:elem) == 1)
    return 1;
 }

 return 0;
}



#######################################################
# hpux_check_patch() returns :                        #
#	1 if the patch is not installed               #
#	0 if installed or not needed                  #
#######################################################

function hpux_check_patch (app, version)
{
 local_var swlist, installed_app, installed_version;

 swlist = get_kb_item ("Host/HP-UX/swlist");
 if ( strlen(app) )
 {
   installed_app = egrep (pattern:string(app,'[\t ]+'), string:swlist);
   if ((installed_app) && !egrep (pattern:"^#.*", string:installed_app))
   {
     if (!isnull (version))
     {
      installed_version = ereg_replace (pattern:string('[\t ]+', app, '[\t ]+(.*)'), replace:"\1", string:installed_app);
      installed_version = chomp (installed_version);
      if (installed_version >< version)
        return 1;
     }
     else
       return 1;
   }
 }
 
 return 0;
}


