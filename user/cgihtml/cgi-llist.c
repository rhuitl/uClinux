/* cgi-llist.c - Minimal linked list library for revised CGI C library
   Eugene Kim, eekim@fas.harvard.edu
   $Id: cgi-llist.c,v 1.2 1996/08/11 04:22:01 eekim Exp $

   Copyright (C) 1995 Eugene Eric Kim
   All Rights Reserved
*/

#include <stdlib.h>
#include <string.h>
#include "cgi-llist.h"
#include "string-lib.h"

void list_create(llist *l)
{
  l->head = 0;
}

node* list_next(node* w)
{
  return w->next;
}

short on_list(llist *l, node* w)
{
  return (w != 0);
}

short on_list_debug(llist *l, node* w)
{
  node* current;

  if (w == 0)
    return 0;
  else {
    current = l->head;
    while ( (current != w) && (current != 0) )
      current = current->next;
    if (current == w)
      return 1;
    else
      return 0;
  }
}

void list_traverse(llist *l, void (*visit)(entrytype item))
{
  node* current;

  current = l->head;
  while (current != 0) {
    (*visit)(current->entry);
    current = current->next;
  }
}

node* list_insafter(llist* l, node* w, entrytype item)
{
  node* newnode = malloc(sizeof(node));

  newnode->entry.name = newstr(item.name);
  newnode->entry.value = newstr(item.value);
  if (l->head == 0) {
    newnode->next = 0;
    l->head = newnode;
  }
  else if (!on_list(l,w))
    /* ERROR: can't insert item after w since w is not on l */
    exit(1);
  else {
    /* insert node after */
    if (newnode == 0) /* can assume that w != NULL */
      /* ERROR: nothing too insert after */
      exit(1);
    else {
      newnode->next = w->next;
      w->next = newnode;
    }
  }
  return newnode;
}

void list_clear(llist* l)
{
  node* lastnode;
  node* nexttolast;
  node* current;

  while (l->head != 0) {
    current = l->head;
    if (current->next == 0) {
      free(current);
      current = 0;
      l->head = current;
    }
    else {
      while ( current->next != 0 ) {
	nexttolast = current;
	lastnode = current->next;
	current = lastnode;
      }
      free(lastnode);
      nexttolast->next = 0;
    }
  }
}
