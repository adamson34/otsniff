# AC-002: Synthetic fixture

## File size

```
-rw-r--r--  1 <user>  staff  1048640 May 19 13:52 tests/fixtures/synthetic-1mb.pcap
```

1,048,640 bytes (exactly 1 MiB).

## Not gitignored

```
$ git check-ignore tests/fixtures/synthetic-1mb.pcap; echo $?
1
```

Exit code 1 = not ignored. The file is committed to the repository.

## Generator

`examples/gen_synthetic_pcap.rs` produces the fixture deterministically.
Running `cargo run --example gen_synthetic_pcap` regenerates it. The example
writes a PCAP with mixed Modbus/TCP, EtherNet/IP, S7Comm, and DHCP traffic
across ~10 000 synthetic packets to reach the 1 MiB target size.
