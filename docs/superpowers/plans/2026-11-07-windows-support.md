# Windows compatibility implementation plan

**Goal:** Build and run RouteScan in Windows PowerShell with working system proxy detection, physical gateway selection, route tracing, and immediate keyboard input.

**Architecture:** Keep shared probing/rendering code; isolate registry and console APIs behind Go OS build constraints. Use built-in `route.exe print -4` and `tracert.exe -d` on Windows. Preserve existing Unix behavior. Reuse the existing x/sys dependency.

- [x] Add regression tests for Windows proxy strings, active routes versus persistent routes/TUN interfaces, localized tracert output and partial loss, HTTP retry timing, and placeholder route rendering.
- [x] Read HKCU Internet Settings; select the lowest-metric active physical IPv4 default route and detect active TUN interfaces. Never derive the Windows gateway by replacing an interface address's last octet.
- [x] Parse Windows tracert samples including `<1`, timeout rows, partial loss, IPv4/IPv6, and partial results on timeout. Report missing trace commands instead of inventing twelve hops.
- [x] Enable Windows console VT output/input, disable line input/echo, restore original modes on exit, and handle escape sequences split across reads. Keep redirected output free of terminal restoration escapes.
- [x] Keep each HTTP attempt's timing isolated and synchronized. Validate local successful, failed TLS, HEAD-to-GET fallback, and concurrent callbacks.
- [x] Document PowerShell build/run commands and remaining network limitations; build, run all tests/vet, cross-compile Unix, and smoke-test Windows reports and keyboard quit.

**Review focus:** Non-English Windows output; TUN more-specific routes; redirected stdio; errors after partial traces; concurrent HTTP callbacks and mode switching. Network reachability and ICMP responses remain properties of the user's network; PAC scripts are not evaluated.
