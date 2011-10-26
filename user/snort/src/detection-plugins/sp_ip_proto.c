/* $Id$ */

/* sp_ip_proto 
 * 
 * Purpose:
 *
 * Check the IP header's protocol field value.
 *
 * Arguments:
 *   
 *   Number, protocol name, ! for negation
 *
 * Effect:
 *
 *  Success on protocol match, failure otherwise 
 *
 * Comments:
 *
 * None.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#ifndef WIN32
#include <netdb.h>
#endif /* !WIN32 */

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "sp_ip_proto.h"


void IpProtoInit(char *, OptTreeNode *, int);
void IpProtoRuleParseFunction(char *, IpProtoData *);
int IpProtoDetectorFunction(Packet *, struct _OptTreeNode *, OptFpList *);



/****************************************************************************
 * 
 * Function: SetupIpProto()
 *
 * Purpose: Generic detection engine plugin ip_proto.  Registers the
 *          configuration function and links it to a rule keyword.  This is
 *          the function that gets called from InitPlugins in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIpProto(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("ip_proto", IpProtoInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: IpProto Setup\n"););
}


/****************************************************************************
 * 
 * Function: IpProtoInit(char *, OptTreeNode *)
 *
 * Purpose: Generic rule configuration function.  Handles parsing the rule 
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpProtoInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *ofl;
    IpProtoData *ipd;
    
    /* multiple declaration check */ 
    /*if(otn->ds_list[PLUGIN_IP_PROTO_CHECK])
    {
        FatalError("%s(%d): Multiple ip_proto options in rule\n", file_name,
                file_line);
    }*/

    ipd = (IpProtoData *) SnortAlloc(sizeof(IpProtoData));

    /* allocate the data structure and attach it to the
       rule's data struct list */
    //otn->ds_list[PLUGIN_IP_PROTO_CHECK] = (IpProtoData *) calloc(sizeof(IpProtoData), sizeof(char));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    IpProtoRuleParseFunction(data, ipd);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    ofl = AddOptFuncToList(IpProtoDetectorFunction, otn);

    ofl->context = ipd;

    /*
    **  Set the ds_list for the first ip_proto check for a rule.  This
    **  is needed for the high-speed rule optimization.
    */
    if(!otn->ds_list[PLUGIN_IP_PROTO_CHECK])
        otn->ds_list[PLUGIN_IP_PROTO_CHECK] = ipd;
}



/****************************************************************************
 * 
 * Function: IpProtoRuleParseFunction(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            ds_ptr => pointer to the IpProtoData struct
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpProtoRuleParseFunction(char *data, IpProtoData *ds_ptr)
{
    //IpProtoData *ds_ptr;  /* data struct pointer */
    struct protoent *pt;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    //ds_ptr = otn->ds_list[PLUGIN_IP_PROTO_CHECK];

    while(isspace((int)*data)) data++;

    if(*data == '!')
    {
        ds_ptr->not_flag = 1;
        data++;
    }

    if(*data == '>')
    {
        ds_ptr->comparison_flag = GREATER_THAN; 
        data++;
    }

    if(*data == '<')
    {
        ds_ptr->comparison_flag = LESS_THAN; 
        data++;
    }

    /* check for a number or a protocol name */
    if(isdigit((int)*data))
    {
        ds_ptr->protocol = atoi(data);
    }
    else
    {
        pt = getprotobyname(data);

        if(pt)
        {
            ds_ptr->protocol = (u_char) pt->p_proto;
        }
        else
        {
            FatalError("%s(%d) => Bad protocol name \"%s\"\n", 
                    file_name, file_line, data);
        }
    } 
}


/****************************************************************************
 * 
 * Function: IpProtoDetectorFunction(char *, OptTreeNode *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 ****************************************************************************/
int IpProtoDetectorFunction(Packet *p, struct _OptTreeNode *otn, 
        OptFpList *fp_list)
{
    IpProtoData *ipd;  /* data struct pointer */

    //ipd = otn->ds_list[PLUGIN_IP_PROTO_CHECK];
    ipd = fp_list->context;

    if(!p->iph)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Not IP\n"););
        return 0;
    }

    switch(ipd->comparison_flag)
    {
        case 0:
            if((ipd->protocol == p->iph->ip_proto) ^ ipd->not_flag)
            {
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
            else
            {
                /* you can put debug comments here or not */
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }

            break;

        case GREATER_THAN:
            if(p->iph->ip_proto > ipd->protocol)
            {
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }

            break;

        default:
            if(p->iph->ip_proto < ipd->protocol)
            {
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }

            break;
    }

    /* if the test isn't successful, this function *must* return 0 */
    return 0;
}
