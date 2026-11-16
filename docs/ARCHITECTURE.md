Data flow: UI -> /api -> ScanManager (validates scope+config) -> ScanRunner thread:
discovery -> per host: chunked TCP/UDP enumeration (nmap or built-in) -> after each chunk: ScanProtection.assess -> investigation registry
(protocol ladder -> HTTP/TLS -> validator -> auth barrier) -> findings -> checkpoint. Everything is persisted as it happens (SQLite),
so cancel/restart/block-pause never lose results; resume skips completed hosts/chunks.
