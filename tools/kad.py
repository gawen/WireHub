#!/usr/bin/env python3

# Study Kademilia graph topology
#
# Usage: wh inspect all | ./kad.py

import sys
import json
from tqdm import tqdm
from collections import defaultdict
import networkx as nx
import random
import time

I = json.load(sys.stdin)

keys = list({v['p']['k'] for v in I})
idx_by_key = {v['p']['k']: str(i) for i, v in enumerate(I)}
K = []
E = defaultdict(dict)
S = set()

def K(x):
    return f'"{x}"'

    if x not in idx_by_key:
        idx_by_key[x] = f'"{len(idx_by_key)}?"'

    return idx_by_key[x]

G = nx.Graph()
G.add_nodes_from(keys)

for p1 in I:
    k1 = p1['p']['k']
    for p2 in p1['peers']:
        k2 = p2['k']

        E[k1][k2] = p2

        ka, kb = sorted((k1, k2))
        S.add(f'{ka} {kb}')

        G.add_edge(k1, k2)

E = dict(E)
print(len(E))

#last_longest_path_ts = time.time()
longest_path = []
try:
    while True:#time.time() - last_longest_path_ts < 10.0:
        k1, k2 = random.choice(keys), random.choice(keys)

        if k1 == k2:
            continue

        p = nx.shortest_path(G, source=k1, target=k2)
        if len(p) == 2:
            continue

        if len(longest_path) >= len(p):
            continue

        longest_path = p
        print("longest path is", len(longest_path))

        #last_longest_path_ts = time.time()
except KeyboardInterrupt:
    pass

print(longest_path)

print(f'wh ipc {longest_path[0]} ping-all {longest_path[-1]}')
print(f'wh ping {longest_path[0]} {longest_path[-1]}')
