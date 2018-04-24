/**
 * @brief A page list based on utlist
 *
 * More about utlist: https://troydhanson.github.io/uthash/utlist.html
 *
 * Created by Siyao Meng on 3/17/18.
 */

#ifndef LINKEDLIST_LNKLIST_H
#define LINKEDLIST_LNKLIST_H

#include "utlist.h"
#include <windows.h>

#include "../Logger/Include/logger.h"
#define Log(...) WriteLog(__FILEW__, __LINE__, __VA_ARGS__)

//#define DebugPageList

#ifdef DebugPageList
#define LogList(...) WriteLog(__FILEW__, __LINE__, __VA_ARGS__)
#else
#define LogList(...)
#endif

#define PAGE_SIZE 4096
//typedef void *PVOID;
//typedef unsigned long ULONG_PTR;
//typedef ULONG_PTR SIZE_T;
//typedef unsigned long ULONG;

/* Definition of page list node */
typedef struct ListNode {
    PVOID BaseAddress;
    SIZE_T RegionSize;
    ULONG Protect;
    struct ListNode *prev; /* needed for a doubly-linked list only */
    struct ListNode *next; /* needed for singly- or doubly-linked lists */
} ListNodeT;

/* Declarations */
void ListInit(void);
void ListDestroy(void);
void ListPrint(void);
ListNodeT *ListNodeNew(PVOID lBaseAddress, SIZE_T lRegionSize, ULONG lProtect);
ListNodeT *ListNodeFindLower(PVOID Address);
void ListNodeDelete(ListNodeT *Curr);
void ListNodeInsert(ListNodeT *Curr);

#endif //LINKEDLIST_LNKLIST_H
