/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003,2004  Aymeric MOIZARD jack@atosc.org
  
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

#ifndef _FIFO_H_
#define _FIFO_H_

#ifdef OSIP_MT
#include <osip2/osip_mt.h>
#endif
#include <osipparser2/osip_list.h>

/**
 * @file osip_fifo.h
 * @brief oSIP fifo Routines
 *
 * This is a very simple implementation of a fifo.
 * <BR>There is not much to say about it...
 */

/**
 * @defgroup oSIP_FIFO oSIP fifo Handling
 * @ingroup osip2_port
 * @{
 */

#ifdef __cplusplus
extern "C"
{
#endif


#ifndef DOXYGEN

#define MAX_LEN 1000
  typedef enum
  { ok, plein, vide }
  osip_fifo_etat;

#endif

/**
 * Structure for referencing a fifo.
 * @var osip_fifo_t
 */
  typedef struct osip_fifo osip_fifo_t;

/**
 * Structure for referencing a fifo.
 * @struct osip_fifo
 */
  struct osip_fifo
  {
#ifdef OSIP_MT
    struct osip_mutex *qislocked;  /**@internal */
    struct osip_sem *qisempty;     /**@internal */
#endif
    osip_list_t *queue;            /**< list of nodes containing elements */
    int nb_elt;                    /**< nb of elements */
    osip_fifo_etat etat;           /**@internal state of the fifo */
  };

/**
 * Initialise a osip_fifo_t element.
 * NOTE: this element MUST be previously allocated.
 * @param ff The element to initialise.
 */
  void osip_fifo_init (osip_fifo_t * ff);
/**
 * Free a fifo element.
 * @param ff The element to work on.
 */
  void osip_fifo_free (osip_fifo_t * ff);
/**
 * Insert an element in a fifo (at the beginning).
 * @param ff The element to work on.
 * @param element The pointer on the element to insert.
 */
  int osip_fifo_insert (osip_fifo_t * ff, void *element);
/**
 * Add an element in a fifo.
 * @param ff The element to work on.
 * @param element The pointer on the element to add.
 */
  int osip_fifo_add (osip_fifo_t * ff, void *element);
/**
 * Get the number of element in a fifo.
 * @param ff The element to work on.
 */
  int osip_fifo_size (osip_fifo_t * ff);
#ifdef OSIP_MT
/**
 * Get an element from a fifo or block until one is added.
 * @param ff The element to work on.
 */
  void *osip_fifo_get (osip_fifo_t * ff);
#endif
/**
 * Try to get an element from a fifo, but do not block if there is no element.
 * @param ff The element to work on.
 */
  void *osip_fifo_tryget (osip_fifo_t * ff);


/** @} */


#ifdef __cplusplus
}
#endif


#endif
