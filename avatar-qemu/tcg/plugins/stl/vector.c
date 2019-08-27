#include <stdio.h>
#include <stdlib.h>
#include "vector.h"

void PrintVector(vector *head)
{
    if (head == NULL)
    {
        printf("  [!] Print exit. Vector is null!\n");
    }
    else
    {
        vector *cur = head;
        while (cur != NULL)
        {
            printf("----------------------------------\n");
            printf("    address=%x\n", cur);
            //printf("    address=%d, size=%d, perms=%c\n", cur->item.mr.address, cur->item.mr.size, cur->item.mr.perms);
            printf("    fp = 0x%x\n", cur->item.cf.fp);
            printf("    sp = 0x%x\n", cur->item.cf.sp);
            printf("    lr = 0x%x\n", cur->item.cf.lr);
            printf("    pc = 0x%x\n", cur->item.cf.pc);
            printf("    before_pc = 0x%x\n", cur->item.cf.before_pc);
            printf("    size = %d\n", cur->item.cf.size);
            cur = cur->next;
        }
    }
}

vector *CreateNodeVector(const vector_item data)
{
    vector *new_node = (vector *)malloc(sizeof(vector));
    if (new_node != NULL)
    {
        new_node->item = data;
        new_node->next = NULL;
    }
    else
    {
        printf("  [-] Malloc error!\n");
    }
    return new_node;
}

vector *PushBackVector(const vector_item data, vector *head)
{
    if (head == NULL)
    {
        head = CreateNodeVector(data);
    }
    else
    {
        vector *cur = head;
        while (cur->next != NULL)
        {
            cur = cur->next;
        }

        vector *new_node = CreateNodeVector(data);
        cur->next = new_node;
    }
    return head;
}

void SwapVectorNode(vector *p1, vector *p2)
{
    vector *tmp = CreateNodeVector(p1->item);
    if (tmp != NULL)
    {
        p1->item = p2->item;
        p2->item = tmp->item;
        free(tmp);
    }
}

vector *GetVectorEnd(vector *head)
{
    if (head == NULL || head->next == NULL)
    {
        return head;
    }
    while (head->next != NULL)
    {
        head = head->next;
    }
    return head;
}

int CmpVectorNode(const vector p1, const vector p2)
{
    if (p1.item.mr.address < p2.item.mr.address)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void QuickSortVector(vector *head, vector *end)
{
    if (head == NULL || end == NULL || head == end)
    {
        return;
    }
    vector *p1 = head;
    vector *p2 = p1->next;
    vector *pivot = head;
    while (p2 != end->next && p2 != NULL)
    {
        if (CmpVectorNode(*p2, *pivot))
        {
            p1 = p1->next;
            SwapVectorNode(p1, p2);
        }
        p2 = p2->next;
    }
    SwapVectorNode(head, p1);
    QuickSortVector(head, p1);
    QuickSortVector(p1->next, end);
}

void BubbleSortVector(vector *head)
{
    if (head == NULL || head->next == NULL)
    {
        return;
    }
    vector *p1 = head;
    for (; p1 != NULL; p1 = p1->next)
    {
        vector *p2 = p1->next;
        for (; p2 != NULL; p2 = p2->next)
        {
            if (CmpVectorNode(*p1, *p2))
            {
                SwapVectorNode(p1, p2);
            }
        }
    }
}

// if vector_item has ptr(linked list, heap memory), it is not correct to call this function to DestoryVector
vector *DestoryVector(vector *head)
{
    vector *p = head;
    vector *q = NULL;
    if (head != NULL)
    {
        while (p->next != NULL)
        {
            q = p->next;
            p->next = q->next;
            free(q);
        }
        if (p->next == NULL)
        {
            free(p);
        }
    }
    return NULL;
}

vector *PopBackVector(vector *head)
{
    if (head == NULL)
    {
        printf("  [-] Pop error! Vector is null!\n");
    }
    else
    {
        vector *p = head;
        vector *q = p->next;
        while (q != NULL && q->next != NULL)
        {
            p = q;
            q = q->next;
        }
        if (q == NULL) // just one node
        {
            head = NULL;
            free(p);
        }
        else
        {
            free(q);
            p->next = NULL;
        }
    }
    return head;
    // no matter how to free, after calling this function,
    // the head is still in the memeory...
    // if return this, means will return NULL.
}

size_t GetVectorSize(vector *head)
{
    vector *cur = head;
    size_t cnt = 0;
    for (; cur != NULL; cur = cur->next)
    {
        cnt++;
    }
    return cnt;
}

vector* ReverseVector(vector *head)
{
    if(head == NULL || head->next == NULL)
    {
        return head;
    }
    vector* p = head, *newH = NULL, *tmp = NULL;
    while(p != NULL){
        tmp = p->next;
        p->next = newH;
        newH = p;
        p = tmp;
    }
    return newH;
}

void simpletest()
{
    memory_range m1 = {100, 1, 'w', 0};
    memory_range m2 = {500, 6, 'r', 1};
    memory_range m3 = {200, 10, 'x', 0};
    memory_range m4 = {300, 8, 'w', 1};
    printf("##### Test begin #####\n");
    printf("--- Create Test ------\n");
    vector_item vit1;
    vit1.mr = m1;
    // vector *v = CreateNodeVector(vit1);
    vector *v = NULL;
    v = PushBackVector(vit1, v);
    PrintVector(v);
    printf("--- Push back Test ---\n");
    vit1.mr = m2;
    v = PushBackVector(vit1, v);
    vit1.mr = m3;
    v = PushBackVector(vit1, v);
    vit1.mr = m4;
    v = PushBackVector(vit1, v);
    PrintVector(v);
    printf("--- Sort Test --------\n");
    BubbleSortVector(v);
    PrintVector(v);
    printf("--- Reverse Test -----\n");
    v = ReverseVector(v);
    PrintVector(v);
    printf("--- Pop back Test1 ---\n");
    v = PopBackVector(v);
    v = PopBackVector(v);
    PrintVector(v);
    printf("--- Get size Test ----\n");
    printf("    Size = %d\n", GetVectorSize(v));
    printf("--- Free Test --------\n");
    v = DestoryVector(v); // head can't free, don't kown why.
    v = PopBackVector(v);
    printf("    Size = %d\n", GetVectorSize(v));
    printf("--- Pop back Test2 ---\n");
    v = PopBackVector(v);
    printf("--- PrintVector Test 2 -----\n");
    PrintVector(v);
    printf("##### Test Finish #####\n");
}

// int rettest(int a)
// {
//     if(a > 10)
//         return NULL;
//     else
//     {
//         return 1;
//     }
// }

int main()
{
    simpletest();
    return 0;
}
