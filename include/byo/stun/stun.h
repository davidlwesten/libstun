#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Milliseconds from a monotonic clock like CLOCK_MONOTONIC
 *
 * Not wall-clock time. Any origin works, only differences matter.
 */
typedef uint64_t stun_time_ms_t;

typedef struct stun_optional_time_ms {
  bool has_value;
  stun_time_ms_t value;
} stun_optional_time_ms_t;

typedef struct stun_ip_address {
  /// IPv4 addresses are IPv4-mapped, ::ffff:a.b.c.d
  uint8_t addr[16];
} stun_ip_address_t;

typedef uint16_t stun_port_t;

typedef struct stun_socket_address {
  stun_ip_address_t ip;
  stun_port_t port;
} stun_socket_address_t;

typedef struct stun_allocator {
  void *(*alloc)(void *ctx, size_t size);
  void (*free)(void *ctx, void *ptr);
  void *ctx;
} stun_allocator_t;

typedef struct stun_rng {
  /// Fills `data` with random bytes, or returns false if it can't. They have
  /// to be cryptographically secure, e.g. from getrandom or arc4random_buf:
  /// they make up the transaction IDs, which keep others from forging
  /// responses.
  bool (*fill)(void *ctx, size_t size, uint8_t data[]);
  void *ctx;
} stun_rng_t;

typedef struct stun_config {
  stun_allocator_t allocator;
  stun_rng_t rng;
  /// How many requests the agent can have in flight at once, 0 for 8
  uint16_t capacity;
} stun_config_t;

typedef struct stun_agent stun_agent_t;

/**
 * @brief Create a STUN agent that talks to one server
 *
 * So far the agent only takes the client's role: it sends requests and handles
 * their responses.
 *
 * `config.rng` is required. If `config.allocator` is left zeroed, malloc and
 * free are used.
 *
 * @param[in] config The agent's configuration, copied into the agent
 *
 * @returns The agent, or nullptr if it couldn't be allocated
 */
stun_agent_t *stun_agent_begin(stun_config_t config);

/**
 * @brief Free the agent, along with any requests still in flight
 */
void stun_agent_end(stun_agent_t *agent);

typedef uint16_t stun_handle_t;

typedef struct stun_handle_or_error {
  bool has_value;
  union {
    stun_handle_t value;
    /// An errno value, e.g. ENOBUFS
    int error;
  };
} stun_handle_or_error_t;

/**
 * @brief Ask the server for the address it sees us at
 *
 * Answered by STUN_EVENT_BOUND or STUN_EVENT_FAILED. Requests go out right
 * away, without waiting for each other.
 *
 * The application should poll the agent afterwards, see stun_agent_poll.
 *
 * @param[in] agent The agent to ask
 *
 * @returns The handle, or an error (ENOBUFS if the agent is at capacity, EIO
 *          if the RNG failed)
 */
stun_handle_or_error_t stun_agent_binding_request(stun_agent_t *agent);

typedef enum stun_failure {
  /// The server didn't answer in time
  STUN_FAILURE_TIMEOUT,
  /// The server's answer couldn't be used, e.g. it had no address
  STUN_FAILURE_INVALID_RESPONSE,
  /// The server answered with an error, see stun_event_t::failed
  STUN_FAILURE_ERROR_RESPONSE,
} stun_failure_t;

/**
 * @brief Something the application has to handle, see stun_agent_poll
 *
 * Later versions may add event types, so ignore any you don't know, e.g. with
 * a default case.
 */
typedef struct stun_event {
  enum {
    /// Send the request described by `send` to the server
    STUN_EVENT_SEND,
    /// The server sees request `bound.handle` coming from `bound.mapped`
    STUN_EVENT_BOUND,
    /// Request `failed.handle` failed for `failed.reason`
    STUN_EVENT_FAILED,
    /// Nothing more to do before `timeout.deadline`, see stun_agent_poll
    STUN_EVENT_TIMEOUT,
  } type;
  union {
    struct {
      size_t size;
      /// Points into the agent and is only valid until the next poll. Copy
      /// it if you want to send it later. If sending fails, it's fine to just
      /// drop it, the retransmission is already scheduled.
      uint8_t const *data;
    } send;
    struct {
      stun_handle_t handle;
      stun_socket_address_t mapped;
    } bound;
    struct {
      stun_handle_t handle;
      stun_failure_t reason;
      /// For STUN_FAILURE_ERROR_RESPONSE, the server's error code from 300 to
      /// 699, e.g. 400 for a bad request or 500 for a temporary problem on the
      /// server's side
      uint16_t error_code;
    } failed;
    struct {
      /// Always later than `now`. Empty if nothing is scheduled, in which case
      /// just wait for the next datagram.
      stun_optional_time_ms_t deadline;
    } timeout;
  };
} stun_event_t;

/**
 * @brief Advance the agent and get the next event
 *
 * Call this until it returns STUN_EVENT_TIMEOUT whenever something happens:
 * a datagram arrived, the deadline passed or a request was made. Then wait
 * until `timeout.deadline` or the next datagram.
 *
 * Every call invalidates the previous event's data (see stun_event_t::send).
 *
 * @param[in] agent The agent to advance
 * @param[in] now   The current time
 *
 * @returns The next event to handle
 */
stun_event_t stun_agent_poll(stun_agent_t *agent, stun_time_ms_t now);

/**
 * @brief Hand a datagram received from the server to the agent
 *
 * Datagrams that don't answer a request in flight are ignored. The first
 * answer to a request decides it.
 *
 * The application should poll the agent afterwards, see stun_agent_poll.
 *
 * @param[in] agent The agent to update
 * @param[in] size  The size of `data`
 * @param[in] data  The datagram's payload
 */
void stun_agent_on_datagram(stun_agent_t *agent,
                            size_t size,
                            uint8_t const data[]);

#ifdef __cplusplus
}
#endif
