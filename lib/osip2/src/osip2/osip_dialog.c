/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <osip2/internal.h>
#include <osip2/osip.h>

#include "fsm.h"
#include <osip2/osip_dialog.h>


void
osip_dialog_set_state (osip_dialog_t * dialog, state_t state)
{
  if (dialog == NULL)
    return ;
  dialog->state = state;
}

int
osip_dialog_update_route_set_as_uas (osip_dialog_t * dialog,
				     osip_message_t * invite)
{
  osip_contact_t *contact;
  int i;

  if (dialog == NULL)
    return -1;
  if (invite == NULL)
    return -1;

  if (osip_list_eol (invite->contacts, 0))
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "missing a contact in invite!\n"));
    }
  else
    {
      if (dialog->remote_contact_uri != NULL)
	{
	  osip_contact_free (dialog->remote_contact_uri);
	}
      dialog->remote_contact_uri = NULL;
      contact = osip_list_get (invite->contacts, 0);
      i = osip_contact_clone (contact, &(dialog->remote_contact_uri));
      if (i != 0)
	return -1;
    }
  return 0;
}

int
osip_dialog_update_osip_cseq_as_uas (osip_dialog_t * dialog,
				     osip_message_t * invite)
{
  if (dialog == NULL)
    return -1;
  if (invite == NULL ||
      invite->cseq == NULL ||
      invite->cseq->number == NULL)
    return -1;

  dialog->remote_cseq = osip_atoi (invite->cseq->number);
  return 0;
}

int
osip_dialog_update_route_set_as_uac (osip_dialog_t * dialog,
				     osip_message_t * response)
{
  /* only the remote target URI is updated here... */
  osip_contact_t *contact;
  int i;

  if (dialog == NULL)
    return -1;
  if (response == NULL)
    return -1;

  if (osip_list_eol (response->contacts, 0))
    {				/* no contact header in response? */
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "missing a contact in response!\n"));
    }
  else
    {
      /* I personally think it's a bad idea to keep the old
         value in case the new one is broken... */
      if (dialog->remote_contact_uri != NULL)
	{
	  osip_contact_free (dialog->remote_contact_uri);
	}
      dialog->remote_contact_uri = NULL;
      contact = osip_list_get (response->contacts, 0);
      i = osip_contact_clone (contact, &(dialog->remote_contact_uri));
      if (i != 0)
	return -1;
    }

  if (dialog->state == DIALOG_EARLY
      && osip_list_size (dialog->route_set) == 0)
    {				/* update the route set */
      int pos = 0;

      while (!osip_list_eol (response->record_routes, pos))
	{
	  osip_record_route_t *rr;
	  osip_record_route_t *rr2;

	  rr =
	    (osip_record_route_t *) osip_list_get (response->record_routes,
						   pos);
	  i = osip_record_route_clone (rr, &rr2);
	  if (i != 0)
	    return -1;
	  osip_list_add (dialog->route_set, rr2, -1);
	  pos++;
	}
    }

  if (MSG_IS_STATUS_2XX (response))
    dialog->state = DIALOG_CONFIRMED;
  return 0;
}

int
osip_dialog_update_tag_as_uac (osip_dialog_t * dialog,
			       osip_message_t * response)
{
  osip_generic_param_t *tag;
  int i;

  if (dialog == NULL)
    return -1;
  if (response == NULL || response->to == NULL)
    return -1;

  i = osip_to_get_tag (response->to, &tag);
  if (i != 0 || tag==NULL || tag->gvalue==NULL)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "Remote UA is not compliant: missing a tag in response!\n"));
      dialog->remote_tag = NULL;
    }
  else
    dialog->remote_tag = osip_strdup (tag->gvalue);
  return 0;
}

int
osip_dialog_match_as_uac (osip_dialog_t * dlg, osip_message_t * answer)
{
  osip_generic_param_t *tag_param_local;
  osip_generic_param_t *tag_param_remote;
  char *tmp;
  int i;

  if (dlg == NULL)
    return -1;
  if (answer == NULL || answer->call_id==NULL ||
      answer->from==NULL || answer->to==NULL)
    return -1;

  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_WARNING, NULL,
	       "Using this method is discouraged. See source code explanations!\n"));
  /*
    When starting a new transaction and when receiving several answers,
    you must be prepared to receive several answers from different sources.
    (because of forking).

    Because some UAs are not compliant (a to tag is missing!), this method
    may match the wrong dialog when a dialog has been created with an empty
    tag in the To header.

    Personnaly, I would recommend to discard 1xx>=101 answers without To tags!
    Just my own feelings.
  */
  osip_call_id_to_str (answer->call_id, &tmp);
  if (0 != strcmp (dlg->call_id, tmp))
    {
      osip_free (tmp);
      return -1;
    }
  osip_free (tmp);

  /* for INCOMING RESPONSE:
     To: remote_uri;remote_tag
     From: local_uri;local_tag           <- LOCAL TAG ALWAYS EXIST
   */
  i = osip_from_get_tag (answer->from, &tag_param_local);
  if (i != 0)
    return -1;
  if (dlg->local_tag == NULL)
    /* NOT POSSIBLE BECAUSE I MANAGE REMOTE_TAG AND I ALWAYS ADD IT! */
    return -1;
  if (0 != strcmp (tag_param_local->gvalue, dlg->local_tag))
    return -1;

  i = osip_to_get_tag (answer->to, &tag_param_remote);
  if (i != 0 && dlg->remote_tag != NULL)	/* no tag in response but tag in dialog */
    return -1;			/* impossible... */
  if (i != 0 && dlg->remote_tag == NULL)	/* no tag in response AND no tag in dialog */
    {
      if (0 ==
	  osip_from_compare ((osip_from_t *) dlg->local_uri,
			     (osip_from_t *) answer->from)
	  && 0 == osip_from_compare (dlg->remote_uri, answer->to))
	return 0;
      return -1;
    }

  if (dlg->remote_tag == NULL)	/* tag in response BUT no tag in dialog */
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "Remote UA is not compliant: missing a tag in To fields!\n"));
      if (0 ==
	  osip_from_compare ((osip_from_t *) dlg->local_uri,
			     (osip_from_t *) answer->from)
	  && 0 == osip_from_compare (dlg->remote_uri, answer->to))
	return 0;
      return -1;
    }

  /* we don't have to compare
     remote_uri with from
     && local_uri with to.    ----> we have both tag recognized, it's enough..
   */
  if (0 == strcmp (tag_param_remote->gvalue, dlg->remote_tag))
    return 0;
  return -1;
}

int
osip_dialog_match_as_uas (osip_dialog_t * dlg, osip_message_t * request)
{
  osip_generic_param_t *tag_param_remote;
  int i;
  char *tmp;

  if (dlg == NULL)
    return -1;
  if (request == NULL || request->call_id==NULL ||
      request->from==NULL || request->to==NULL)
    return -1;

  osip_call_id_to_str (request->call_id, &tmp);
  if (0 != strcmp (dlg->call_id, tmp))
    {
      osip_free (tmp);
      return -1;
    }
  osip_free (tmp);

  /* for INCOMING REQUEST:
     To: local_uri;local_tag           <- LOCAL TAG ALWAYS EXIST
     From: remote_uri;remote_tag
   */

  if (dlg->local_tag == NULL)
    /* NOT POSSIBLE BECAUSE I MANAGE REMOTE_TAG AND I ALWAYS ADD IT! */
    return -1;

  i = osip_from_get_tag (request->from, &tag_param_remote);
  if (i != 0 && dlg->remote_tag != NULL)	/* no tag in request but tag in dialog */
    return -1;			/* impossible... */
  if (i != 0 && dlg->remote_tag == NULL)	/* no tag in request AND no tag in dialog */
    {
      if (0 ==
	  osip_from_compare ((osip_from_t *) dlg->remote_uri,
			     (osip_from_t *) request->from)
	  && 0 == osip_from_compare (dlg->local_uri, request->to))
	return 0;
      return -1;
    }

  if (dlg->remote_tag == NULL)	/* tag in response BUT no tag in dialog */
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "Remote UA is not compliant: missing a tag in To feilds!\n"));
      if (0 ==
	  osip_from_compare ((osip_from_t *) dlg->remote_uri,
			     (osip_from_t *) request->from)
	  && 0 == osip_from_compare (dlg->local_uri, request->to))
	return 0;
      return -1;
    }
  /* we don't have to compare
     remote_uri with from
     && local_uri with to.    ----> we have both tag recognized, it's enough..
   */
  if (0 == strcmp (tag_param_remote->gvalue, dlg->remote_tag))
    return 0;

  return -1;
}

int
osip_dialog_init_as_uac (osip_dialog_t ** dialog, osip_message_t * response)
{
  int i;
  int pos;
  osip_generic_param_t *tag;

  *dialog = NULL;

  (*dialog) = (osip_dialog_t *) osip_malloc (sizeof (osip_dialog_t));
  if (*dialog == NULL)
    return -1;

  memset (*dialog, 0, sizeof (osip_dialog_t));

  (*dialog)->your_instance = NULL;

  (*dialog)->type = CALLER;
  if (MSG_IS_STATUS_2XX (response))
    (*dialog)->state = DIALOG_CONFIRMED;
  else				/* 1XX */
    (*dialog)->state = DIALOG_EARLY;

  i = osip_call_id_to_str (response->call_id, &((*dialog)->call_id));
  if (i != 0)
    goto diau_error_0;

  i = osip_from_get_tag (response->from, &tag);
  if (i != 0)
    goto diau_error_1;
  (*dialog)->local_tag = osip_strdup (tag->gvalue);

  i = osip_to_get_tag (response->to, &tag);
  if (i != 0)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "Remote UA is not compliant: missing a tag in response!\n"));
      (*dialog)->remote_tag = NULL;
    }
  else
    (*dialog)->remote_tag = osip_strdup (tag->gvalue);

  (*dialog)->route_set = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*dialog)->route_set);

  pos = 0;
  while (!osip_list_eol (response->record_routes, pos))
    {
      osip_record_route_t *rr;
      osip_record_route_t *rr2;

      rr =
	(osip_record_route_t *) osip_list_get (response->record_routes, pos);
      i = osip_record_route_clone (rr, &rr2);
      if (i != 0)
	goto diau_error_2;
      osip_list_add ((*dialog)->route_set, rr2, -1);
      pos++;
    }

  (*dialog)->local_cseq = osip_atoi (response->cseq->number);
  (*dialog)->remote_cseq = -1;

  i = osip_to_clone (response->to, &((*dialog)->remote_uri));
  if (i != 0)
    goto diau_error_3;

  i = osip_from_clone (response->from, &((*dialog)->local_uri));
  if (i != 0)
    goto diau_error_4;

  {
    osip_contact_t *contact;

    if (!osip_list_eol (response->contacts, 0))
      {
	contact = osip_list_get (response->contacts, 0);
	i = osip_contact_clone (contact, &((*dialog)->remote_contact_uri));
	if (i != 0)
	  goto diau_error_5;
      }
    else
      {
	(*dialog)->remote_contact_uri = NULL;
	OSIP_TRACE (osip_trace
		    (__FILE__, __LINE__, OSIP_WARNING, NULL,
		     "Remote UA is not compliant: missing a contact in response!\n"));
      }
  }
  (*dialog)->secure = -1;	/* non secure */

  return 0;

diau_error_5:
  osip_from_free ((*dialog)->local_uri);
diau_error_4:
  osip_from_free ((*dialog)->remote_uri);
diau_error_3:
diau_error_2:
  osip_list_special_free ((*dialog)->route_set,
			  (void *(*)(void *)) &osip_record_route_free);
  osip_free ((*dialog)->remote_tag);
  osip_free ((*dialog)->local_tag);
diau_error_1:
  osip_free ((*dialog)->call_id);
diau_error_0:
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_ERROR, NULL,
	       "Could not establish dialog!\n"));
  osip_free (*dialog);
  *dialog = NULL;
  return -1;
}

#if 1				/* SIPIT13 */
int
osip_dialog_init_as_uac_with_remote_request (osip_dialog_t ** dialog,
					     osip_message_t * next_request,
					     int local_cseq)
{
  int i;
  osip_generic_param_t *tag;

  *dialog = NULL;

  (*dialog) = (osip_dialog_t *) osip_malloc (sizeof (osip_dialog_t));
  if (*dialog == NULL)
    return -1;

  memset (*dialog, 0, sizeof (osip_dialog_t));
  (*dialog)->your_instance = NULL;

  (*dialog)->type = CALLER;
#if 0
  (*dialog)->state = DIALOG_CONFIRMED;
#endif
  (*dialog)->state = DIALOG_EARLY;

  i = osip_call_id_to_str (next_request->call_id, &((*dialog)->call_id));
  if (i != 0)
    goto diau_error_0;

  i = osip_from_get_tag (next_request->to, &tag);
  if (i != 0)
    goto diau_error_1;
  (*dialog)->local_tag = osip_strdup (tag->gvalue);

  i = osip_to_get_tag (next_request->from, &tag);
  if (i != 0)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "Remote UA is not compliant: missing a tag in next request!\n"));
      (*dialog)->remote_tag = NULL;
    }
  else
    (*dialog)->remote_tag = osip_strdup (tag->gvalue);

  (*dialog)->route_set = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*dialog)->route_set);

  (*dialog)->local_cseq = local_cseq;	/* -1 osip_atoi (xxx->cseq->number); */
  (*dialog)->remote_cseq = osip_atoi (next_request->cseq->number);

  i = osip_to_clone (next_request->from, &((*dialog)->remote_uri));
  if (i != 0)
    goto diau_error_3;

  i = osip_from_clone (next_request->to, &((*dialog)->local_uri));
  if (i != 0)
    goto diau_error_4;

  {
    osip_contact_t *contact;

    if (!osip_list_eol (next_request->contacts, 0))
      {
	contact = osip_list_get (next_request->contacts, 0);
	i = osip_contact_clone (contact, &((*dialog)->remote_contact_uri));
	if (i != 0)
	  goto diau_error_5;
      }
    else
      {
	(*dialog)->remote_contact_uri = NULL;
	OSIP_TRACE (osip_trace
		    (__FILE__, __LINE__, OSIP_WARNING, NULL,
		     "Remote UA is not compliant? missing a contact in response!\n"));
      }
  }

  (*dialog)->secure = -1;	/* non secure */

  return 0;

diau_error_5:
  osip_from_free ((*dialog)->local_uri);
diau_error_4:
  osip_from_free ((*dialog)->remote_uri);
diau_error_3:
  osip_free ((*dialog)->remote_tag);
  osip_free ((*dialog)->local_tag);
diau_error_1:
  osip_free ((*dialog)->call_id);
diau_error_0:
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_ERROR, NULL,
	       "Could not establish dialog!\n"));
  osip_free (*dialog);
  *dialog = NULL;
  return -1;
}
#endif

int
osip_dialog_init_as_uas (osip_dialog_t ** dialog, osip_message_t * invite,
			 osip_message_t * response)
{
  int i;
  int pos;
  osip_generic_param_t *tag;

  (*dialog) = (osip_dialog_t *) osip_malloc (sizeof (osip_dialog_t));
  if (*dialog == NULL)
    return -1;

  memset (*dialog, 0, sizeof (osip_dialog_t));
  (*dialog)->your_instance = NULL;

  (*dialog)->type = CALLEE;
  if (MSG_IS_STATUS_2XX (response))
    (*dialog)->state = DIALOG_CONFIRMED;
  else				/* 1XX */
    (*dialog)->state = DIALOG_EARLY;

  i = osip_call_id_to_str (response->call_id, &((*dialog)->call_id));
  if (i != 0)
    goto diau_error_0;

  i = osip_to_get_tag (response->to, &tag);
  if (i != 0)
    goto diau_error_1;
  (*dialog)->local_tag = osip_strdup (tag->gvalue);

  i = osip_from_get_tag (response->from, &tag);
  if (i != 0)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "Remote UA is not compliant: missing a tag in response!\n"));
      (*dialog)->remote_tag = NULL;
    }
  else
    (*dialog)->remote_tag = osip_strdup (tag->gvalue);

  (*dialog)->route_set = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*dialog)->route_set);

  pos = 0;
  while (!osip_list_eol (response->record_routes, pos))
    {
      osip_record_route_t *rr;
      osip_record_route_t *rr2;

      rr =
	(osip_record_route_t *) osip_list_get (response->record_routes, pos);
      i = osip_record_route_clone (rr, &rr2);
      if (i != 0)
	goto diau_error_2;
      osip_list_add ((*dialog)->route_set, rr2, -1);
      pos++;
    }

  /* local_cseq is set to response->cseq->number for better
     handling of bad UA */
  (*dialog)->local_cseq = osip_atoi (response->cseq->number);
  (*dialog)->remote_cseq = osip_atoi (response->cseq->number);


  i = osip_from_clone (response->from, &((*dialog)->remote_uri));
  if (i != 0)
    goto diau_error_3;

  i = osip_to_clone (response->to, &((*dialog)->local_uri));
  if (i != 0)
    goto diau_error_4;

  {
    osip_contact_t *contact;

    if (!osip_list_eol (invite->contacts, 0))
      {
	contact = osip_list_get (invite->contacts, 0);
	i = osip_contact_clone (contact, &((*dialog)->remote_contact_uri));
	if (i != 0)
	  goto diau_error_5;
      }
    else
      {
	(*dialog)->remote_contact_uri = NULL;
	OSIP_TRACE (osip_trace
		    (__FILE__, __LINE__, OSIP_WARNING, NULL,
		     "Remote UA is not compliant: missing a contact in response!\n"));
      }
  }
  (*dialog)->secure = -1;	/* non secure */

  return 0;

diau_error_5:
  osip_from_free ((*dialog)->local_uri);
diau_error_4:
  osip_from_free ((*dialog)->remote_uri);
diau_error_3:
diau_error_2:
  osip_list_special_free ((*dialog)->route_set,
			  (void *(*)(void *)) &osip_record_route_free);
  osip_free ((*dialog)->remote_tag);
  osip_free ((*dialog)->local_tag);
diau_error_1:
  osip_free ((*dialog)->call_id);
diau_error_0:
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_ERROR, NULL,
	       "Could not establish dialog!\n"));
  osip_free (*dialog);
  *dialog = NULL;
  return -1;
}

void
osip_dialog_free (osip_dialog_t * dialog)
{
  if (dialog == NULL)
    return;
  osip_contact_free (dialog->remote_contact_uri);
  osip_from_free (dialog->local_uri);
  osip_to_free (dialog->remote_uri);
  osip_list_special_free (dialog->route_set,
			  (void *(*)(void *)) &osip_record_route_free);
  osip_free (dialog->remote_tag);
  osip_free (dialog->local_tag);
  osip_free (dialog->call_id);
  osip_free (dialog);
}
