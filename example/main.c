// Asks a STUN server for the address it sees us at:
//
//   stunc stun.example.org
//   stunc 192.0.2.1 3478
//   stunc 2001:db8::1

#include <byo/stun/stun.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static stun_time_ms_t now() {
  struct timespec ts = {};
  [[maybe_unused]] int const result = clock_gettime(CLOCK_MONOTONIC, &ts);
  assert(result == 0);
  return (stun_time_ms_t)ts.tv_sec * 1000 +
         (stun_time_ms_t)ts.tv_nsec / 1000000;
}

static bool fill(void * /*ctx*/, size_t size, uint8_t data[]) {
  size_t filled = 0;
  while (filled < size) {
    ssize_t const result = getrandom(data + filled, size - filled, 0);
    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    filled += (size_t)result;
  }
  return true;
}

// a UDP socket that only talks to the server
static int connect_to_server(char const *server, char const *port) {
  struct addrinfo const hints = {
      .ai_socktype = SOCK_DGRAM,
      .ai_flags = AI_NUMERICSERV,
  };
  struct addrinfo *addresses = nullptr;
  int const error = getaddrinfo(server, port, &hints, &addresses);
  if (error != 0) {
    fprintf(stderr, "%s: %s\n", server, gai_strerror(error));
    exit(EXIT_FAILURE);
  }

  // the first address will do
  int const fd = socket(addresses->ai_family, addresses->ai_socktype,
                        addresses->ai_protocol);
  if (fd == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  if (connect(fd, addresses->ai_addr, addresses->ai_addrlen) == -1) {
    perror("connect");
    exit(EXIT_FAILURE);
  }

  freeaddrinfo(addresses);
  return fd;
}

// wait for a datagram until the deadline, if any, and hand it to the agent
static void
receive(int fd, stun_agent_t *agent, stun_optional_time_ms_t deadline) {
  int timeout = -1;
  if (deadline.has_value) {
    auto const current = now();
    timeout = deadline.value > current ? (int)(deadline.value - current) : 0;
  }

  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  int const ready = poll(&pfd, 1, timeout);
  if (ready == -1) {
    perror("poll");
    exit(EXIT_FAILURE);
  }

  if (ready == 0) {
    // the deadline passed
    return;
  }

  uint8_t data[1500];
  ssize_t const size = recv(fd, data, sizeof(data), 0);
  if (size == -1) {
    // e.g. ECONNREFUSED when nothing listens on the server, the
    // retransmissions keep trying
    perror("recv");
    return;
  }

  stun_agent_on_datagram(agent, (size_t)size, data);
}

static void print_address(stun_socket_address_t const *address) {
  static uint8_t const v4_mapped[12] = {[10] = 0xFF, 0xFF};
  char text[INET6_ADDRSTRLEN];
  if (memcmp(address->ip.addr, v4_mapped, sizeof(v4_mapped)) == 0) {
    inet_ntop(AF_INET, address->ip.addr + 12, text, sizeof(text));
    printf("%s:%u\n", text, address->port);
  } else {
    inet_ntop(AF_INET6, address->ip.addr, text, sizeof(text));
    printf("[%s]:%u\n", text, address->port);
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2 && argc != 3) {
    fprintf(stderr, "usage: %s <server> [port]\n", argv[0]);
    fprintf(stderr, "e.g.   %s stun.example.org\n", argv[0]);
    fprintf(stderr, "       %s 192.0.2.1 3478\n", argv[0]);
    return EXIT_FAILURE;
  }

  int const fd = connect_to_server(argv[1], argc == 3 ? argv[2] : "3478");

  stun_agent_t *const agent =
      stun_agent_begin((stun_config_t){.rng = {.fill = fill}});
  if (!agent) {
    fprintf(stderr, "out of memory\n");
    return EXIT_FAILURE;
  }

  auto const request = stun_agent_binding_request(agent);
  if (!request.has_value) {
    fprintf(stderr, "stun_agent_binding_request: %s\n",
            strerror(request.error));
    return EXIT_FAILURE;
  }

  int status = EXIT_FAILURE;
  for (bool running = true; running;) {
    auto const event = stun_agent_poll(agent, now());
    switch (event.type) {
    case STUN_EVENT_SEND:
      if (send(fd, event.send.data, event.send.size, 0) == -1) {
        // the retransmission is already scheduled
        perror("send");
      }
      break;
    case STUN_EVENT_BOUND:
      print_address(&event.bound.mapped);
      status = EXIT_SUCCESS;
      running = false;
      break;
    case STUN_EVENT_FAILED:
      fprintf(stderr, "the server didn't answer\n");
      running = false;
      break;
    case STUN_EVENT_TIMEOUT:
      receive(fd, agent, event.timeout.deadline);
      break;
    }
  }

  stun_agent_end(agent);
  close(fd);
  return status;
}
