### Source

[SharpNoPSExec](https://github.com/juliourena/SharpNoPSExec)

### Detect

1. Sysmon 13 or WinEventLog 4657 - последовательность из 2х событий (одинаковый ID), в которых ImagePath сначала меняется на вредоносный, а потом возвращается к исходному значению (ImagePath: одинаковое имя службы, но разные значения).
2. WinEventLog 4624 (LogonType 3) -> 4674 (SC Manager)[1, ]: одинаковые domain\user, LogonId, С конкретным запрашиваемым доступом.

3. WinEventLog: Service Control Manager - бесполезны.
4. WinEventLog 4663s - неинформативно.
5. WinEventLog 5145 - отсутствуют, т.к. подключение производится через RPC (есть пример pcap)