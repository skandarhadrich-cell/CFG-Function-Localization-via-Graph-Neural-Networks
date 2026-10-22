# Three-target split

Protocol: `three-target-cluster-stratified-v3`  
Assignment SHA-256: `328e8f21f71f31904777e208d86e816523a646834d5eaaad884236d41a72103c`  
Samples: **2733**; clusters: **303**; optimizer loss: **0.42544435**

| split | samples | clusters | anti_debug | keylogger | injection |
|---|---:|---:|---:|---:|---:|
| train | 1913 | 106 | 394 | 950 | 944 |
| val | 410 | 85 | 27 | 152 | 203 |
| test | 410 | 112 | 27 | 153 | 202 |

The split is grouped by `cluster_key`; every sample of a cluster is in one split. Sample counts follow 70/15/15 and target-positive functions follow the same proportions as closely as the cluster groups allow. The optimizer places the dominant keylogger cluster in train and keeps at least 20 positives per target in validation and test.
