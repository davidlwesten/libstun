# libstun

[![CI](https://github.com/byo-io/libstun/actions/workflows/ci.yml/badge.svg)](https://github.com/byo-io/libstun/actions/workflows/ci.yml)

A library for Session Traversal Utilities for NAT ([RFC 8489]), written in
C23.

STUN lets a host behind a NAT ask a server on the other side which address
and port its packets come from. Any STUN agent can be the client in one
exchange and the server in the next, and this library is meant to be either.
So far it takes the client's role: it builds requests, retransmits them and
tells the application how the server answered.

It sends Binding requests over UDP and reports the mapped address.

[RFC 8489]: https://www.rfc-editor.org/rfc/rfc8489

## Sans-IO

The library never touches the network or the clock. The application owns the
socket, the time and the source of randomness, and the library is a state
machine in between:

- the application hands it received datagrams and the current time
- the library tells it what to send and how long it can sleep

That keeps the library small and deterministic. It works with any event loop
or socket API, and the tests can drive it through retransmissions without
waiting for anything.

## Usage

The application makes requests, then calls `stun_session_poll` until it
returns `STUN_EVENT_TIMEOUT`, handles the events in between and waits for a
datagram or the deadline:

```c
// fill_random writes cryptographically secure random bytes, e.g. with
// getrandom or arc4random_buf
stun_session_t *session =
    stun_session_begin((stun_config_t){.rng = {.fill = fill_random}});

auto const request = stun_session_binding_request(session);

while (running) {
  stun_event_t event;
  do {
    event = stun_session_poll(session, now_ms());
    switch (event.type) {
    case STUN_EVENT_SEND:
      // to the server, port 3478 unless it says otherwise
      send(socket, event.send.data, event.send.size, 0);
      break;
    case STUN_EVENT_BOUND:
      // the server sees event.bound.handle coming from event.bound.mapped
      break;
    case STUN_EVENT_FAILED:
    case STUN_EVENT_TIMEOUT:
      break;
    }
  } while (event.type != STUN_EVENT_TIMEOUT);

  // wait for a datagram or until event.timeout.deadline, and hand any datagram
  // from the server to stun_session_on_datagram(session, size, data)
}

stun_session_end(session);
```

Requests go out right away, up to the session's capacity (8 by default), and
each is retransmitted as RFC 8489 has it until it's answered or fails 39.5 s
after it was first sent.

`example/` has a complete client using a UDP socket and `poll`.

## Building

libstun needs a C23 compiler and CMake 3.23 or newer to build, or CMake 3.28
with the tests. CI builds with GCC 14 and Clang 20.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

The tests download [Unity] and run with AddressSanitizer and
UndefinedBehaviorSanitizer. Without network access,
`-DFETCHCONTENT_TRY_FIND_PACKAGE_MODE=ALWAYS` uses an installed Unity instead.

[Unity]: https://github.com/ThrowTheSwitch/Unity

The wire format is generated from `lib/stun.pkt` by [pktc], along with a
libFuzzer harness for it. To build and run the harness (clang only):

```sh
cmake -S . -B build -DCMAKE_C_COMPILER=clang -DSTUN_BUILD_FUZZER=ON
cmake --build build
./build/test/stun_fuzz -max_total_time=60
```

[pktc]: https://github.com/davidlwesten/pktc

The example client takes the server's address or hostname, and optionally a
port:

```sh
./build/example/stunc stun.example.org
./build/example/stunc 192.0.2.1 3478
```

## License

MIT, see [LICENSE](LICENSE).
