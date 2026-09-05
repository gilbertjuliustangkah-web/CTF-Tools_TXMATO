# CTF-Tools_TXMATO
CTF Tools Hybrid, CLI and Local Web
                    ┌──────────────────────┐
                    │     CTF TOOLKIT      │
                    │      Core Engine     │
                    └──────────┬───────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
       ┌──────▼──────┐                   ┌──────▼──────┐
       │     CLI     │                   │  Local Web  │
       │             │                   │   Dashboard │
       │ ctf scan    │                   │ localhost   │
       │ ctf crypto  │                   │ :8080       │
       │ ctf pwn     │                   │             │
       │ ctf web     │                   │ Scan / Logs │
       └─────────────┘                   └─────────────┘

        ┌──────────────────────────────────────────────┐
        │ CTF TOOLKIT                                  │
        ├───────────┬──────────────────────────────────┤
        │ Dashboard │ Target: 10.10.10.5               │
        │ Targets   │                                  │
        │ Recon     │ Ports                            │
        │ Web       │ 22   SSH                         │
        │ Crypto    │ 80   HTTP                        │
        │ Forensics │ 443  HTTPS                       │
        │ Reverse   │                                  │
        │ Pwn       │ Findings                         │
        │ Terminal  │ 3 interesting endpoints          │
        │ Workspace │                                  │
        └───────────┴──────────────────────────────────┘
