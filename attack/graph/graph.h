#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


#ifndef GRAPH
typedef struct NdCo
{
    size_t i;
    size_t j;
    uint32_t t;
}NdCo;

typedef struct Node
{
    NdCo self;
    NdCo p1;
    NdCo p2;
    NdCo p3;
}Node;

typedef Node *Graph;

typedef struct LNode
{
    NdCo c;
    size_t lay;
    size_t seg;
    size_t posL;
    size_t posS;
    unsigned np;
    size_t p1;
    size_t p2;
    size_t p3;
}LNode;

typedef LNode *LGraph;
#define GRAPH
#endif


void genGraph(size_t ll, uint32_t iters, size_t q, Graph ret);

void linGraph(Graph g, size_t layers[], size_t para, size_t q, size_t nds, LGraph h);

void setLayers(LGraph g, size_t nds, size_t layers[]);

void setSegments(LGraph g, size_t nds, size_t *segs[]);
