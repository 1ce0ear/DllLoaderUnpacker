/**
 * @brief Implementation of a page list based on utlist
 *
 * More about utlist: https://troydhanson.github.io/uthash/utlist.html
 *
 * Created by Siyao Meng on 3/17/18.
 */

#include "Include/pagelist.h"
#include <stdlib.h>
#include <windows.h>

/* Global list head */
static ListNodeT *head = NULL;

/* Print the list for debugging. */
void ListPrint(void) {
    ListNodeT *elt;
    ULONG EndAddr;
    DL_FOREACH(head, elt) {
        EndAddr = (ULONG)elt->BaseAddress + elt->RegionSize;
        LogList(L"BA=0x%08lx, RS=%zu, Prot=0x%08lx, EndAddr(excl)=0x%08lx"
			L", Curr=%p, prev=%p, next=%p",
               (ULONG)elt->BaseAddress, elt->RegionSize, elt->Protect, EndAddr, 
			elt, elt->prev, elt->next);
    }
}

/* Compare node function */
static int CompNode(ListNodeT *n1, ListNodeT *n2) {
    return (int)n1->BaseAddress - (int)n2->BaseAddress;
}

/* Create new node */
ListNodeT *ListNodeNew(PVOID lBaseAddress, SIZE_T lRegionSize, ULONG lProtect) {
    ListNodeT *node = malloc(sizeof(ListNodeT));
    if (node == NULL) return NULL;

    node->BaseAddress = lBaseAddress;
    node->RegionSize = lRegionSize;
    node->Protect = lProtect;
    node->prev = node->next = NULL;
    return node;
}

/* Find node */
ListNodeT *ListNodeFindLower(PVOID Address) {
    ListNodeT *Curr;
	ListNodeT *Next;

    DL_FOREACH(head, Curr) {
		Next = Curr->next;
		//Log(L"Curr=%p, Next=%p", Curr, Next);
        if ((ULONG)Address < (ULONG)Curr->BaseAddress) {
			return NULL;
		}
		else if (Next) {
			if ((ULONG)Next->BaseAddress > (ULONG)Address) {
				return Curr;
			}
		}
		else {
			return Curr;
		}
    }

    return NULL;
}

/* Delete node from the list. NOTE: You need to manually free the node */
void ListNodeDelete(ListNodeT *Curr) {
    DL_DELETE(head, Curr);
}

/* Insert node to the list and perform checking */
void ListNodeInsert(ListNodeT *Curr) {

    /* Sanity check */
    if (Curr == NULL) return;

    if (Curr->RegionSize % PAGE_SIZE != 0) {
		LogList(L"Invalid size: not aligned to PAGE_SIZE. Aborting insertion.");
        return;
    }

    /* Insert directly */
	LogList(L"Inserting: BA=0x%08lx, RS=%lu, Prot=0x%08lx",
           (ULONG)Curr->BaseAddress, Curr->RegionSize, Curr->Protect);

	/* Check existence */
	ListNodeT *out;
	DL_SEARCH(head, out, Curr, CompNode);
	if (out != NULL) {
		if (out->RegionSize >= Curr->RegionSize) {
			LogList(L"Node with same BaseAddress exists! Shrinking RS.");
			out->RegionSize = Curr->RegionSize;
			out->Protect = Curr->Protect;
			/* Justification needed */
			free(Curr);
			return;
		}
		else {
			LogList(L"Node with same BaseAddress exists! Enlarging RS.");
			ListNodeDelete(out);
		}
	}

	//LogList(L"Current content:");
	//ListPrint();

	// The macro doesn't work well with C mode in VS: LDECLTYPE
    //DL_INSERT_INORDER(head, Curr, CompNode);
	ListNodeT *elt;
	if (head) {
		DL_LOWER_BOUND(head, elt, Curr, CompNode);
		DL_APPEND_ELEM(head, elt, Curr);
	}
	else {
		(head) = (Curr);
		(head)->prev = (head);
		(head)->next = NULL;
	}

    /* Assumed success */

	LogList(L"Inserted.  Before combine/overlap/split:");
    ListPrint();

    ListNodeT *Prev = Curr->prev, *Next = Curr->next;
    ULONG CurrEndAddr = (ULONG)Curr->BaseAddress + Curr->RegionSize;

    /* Check prev */
    if (Prev != NULL && Curr != Prev && head != Curr) {
        ULONG PrevEndAddr = (ULONG)Prev->BaseAddress + Prev->RegionSize;
        /* Check combine and overlap */
        if (PrevEndAddr >= CurrEndAddr) {
            if (Prev->Protect == Curr->Protect) {
                /* Combine. Prev node includes current, delete current */
				/* Remove the node from the list. */
                ListNodeDelete(Curr);
				/* Then free the node. */
                free(Curr);
				/* Set the pointer to NULL to avoid accidental use-after-free.*/
                Curr = NULL;
            } else {
                /* Split prev node into two nodes, one before and one after. */
                PVOID AfterBaseAddress = (PVOID)CurrEndAddr;
                SIZE_T AfterRegionSize = PrevEndAddr - CurrEndAddr;
                ULONG AfterProtect = Prev->Protect;
                ListNodeT *after = ListNodeNew(AfterBaseAddress,
                                               AfterRegionSize, AfterProtect);

                /* Modify prev node */
                Prev->RegionSize = (ULONG)Curr->BaseAddress 
									- (ULONG)Prev->BaseAddress;

                ListNodeInsert(after);
            }
        }
        else if (PrevEndAddr >= (ULONG)Curr->BaseAddress) {
			/* If prev and curr has the same Protect bits. */
            if (Prev->Protect == Curr->Protect) {
                /* Combine, update current node and delete previous node */
                /* WARNING: NOT THREAD SAFE! */
                Curr->BaseAddress = Prev->BaseAddress;
                Curr->RegionSize = CurrEndAddr - (ULONG) Prev->BaseAddress;

                ListNodeDelete(Prev);
                free(Prev);
            } else {
                /* Deal with overlap */
                Prev->RegionSize = (ULONG)Curr->BaseAddress
                                   - (ULONG)Prev->BaseAddress;
            }
        }
    }

    /* Check next */
    while (Curr != NULL && Next != NULL && Curr != Next) {
        ULONG NextEndAddr = (ULONG)Next->BaseAddress + Next->RegionSize;
        /* Check combine and overlap */
        if (CurrEndAddr >= (ULONG)Next->BaseAddress) {
            if (CurrEndAddr >= NextEndAddr) {
                /* Completely overwritten, delete next node */
                ListNodeDelete(Next);

                ListNodeT *temp = Next;
                /* Careful with UAF! */
                Next = Next->next;
                free(temp);

                /* Carry on, probably more nodes to be overwritten */
                continue;
            } else {
                /* Partially overwritten, two cases */
                if (Next->Protect == Curr->Protect) {
                    /* Combine, update current node and delete next node */
                    Curr->RegionSize = NextEndAddr - (ULONG)Curr->BaseAddress;

                    ListNodeDelete(Next);
                    free(Next);
                } else {
                    /* update next->BaseAddress */
                    Next->RegionSize = NextEndAddr - CurrEndAddr;
                    Next->BaseAddress = (PVOID) CurrEndAddr;
                    /* Assumed alignment! */
                }

                break;
            }
        } else {
            break;
        }
    }

	LogList(L"After:");
    ListPrint();

    // Test find
//    Curr = ListNodeFindLower((PVOID) 0x01003000);
//    LogList(L"res->BA=0x%08lx", (ULONG)Curr->BaseAddress);
}
