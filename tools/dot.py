#!/usr/bin/env python3

# Generate a Graphviz DOT file to look at the Kademilia DHT
#
# Usage: wh inspect all | ./dot.py > kad.dot
#        xdot kad.dot

import sys
import json
from collections import defaultdict

I = json.load(sys.stdin)

def arrow(p):
    if p.get('alias', False):
        return 'odiamond'

    elif p.get('relay', None):
        return 'odot'

    elif p.get('is_nated', False) and p.get('addr', None):
        return 'open'

    elif p.get('addr', None):
        return 'normal'

    else:
        return 'none'

print('digraph {')

keys = {v['p']['k'] for v in I}
idx_by_key = {v['p']['k']: str(i) for i, v in enumerate(I)}
K = []
G = defaultdict(dict)
S = set()

def K(x):
    return f'"{x}"'

    if x not in idx_by_key:
        idx_by_key[x] = f'"{len(idx_by_key)}?"'

    return idx_by_key[x]

for p1 in I:
    k1 = p1['p']['k']
    for p2 in p1['peers']:
        k2 = p2['k']

        G[k1][k2] = p2

        ka, kb = sorted((k1, k2))
        S.add(f'{ka} {kb}')

for s in sorted(S):
    s = s.split()

    attrs = {}

    head = tail = False

    if s[1] in G[s[0]]:
        head = True
        attrs['arrowhead'] = arrow(G[s[0]][s[1]])

    if s[0] in G[s[1]]:
        tail = True
        attrs['arrowtail'] = arrow(G[s[1]][s[0]])

    if head and tail:
        attrs['dir'] = 'both'

    elif tail:
        attrs['dir'] = 'back'

    elif head:
        attrs['dir'] = 'front'

    else:
        raise Exception()

    attrs = ' '.join(f'{k}={v}' for k, v in sorted(attrs.items()))
    print(f'  {K(s[0])} -> {K(s[1])} [{attrs}];')

print('}')

