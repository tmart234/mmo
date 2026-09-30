# client-core

The reference client library and `client-sim`, a CLI for smoke tests. It
requests admission from the Verifier and Broker (an AR and a SAT), joins
the game server over `fpp-session` (AdmitPop, SAR-chain checks), sends
InputFrames and signs InputCommits, and stops when the server's SAR chain
lapses.
