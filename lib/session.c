#include <byo/stun/stun.h>

#include "message.h"
#include "retransmit.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC(allocator, ...) (allocator.alloc(allocator.ctx, __VA_ARGS__))
#define FREE(allocator, ...) (allocator.free(allocator.ctx, __VA_ARGS__))

static constexpr uint16_t STUN_DEFAULT_CAPACITY = 8;

// a Binding request without attributes is just the header
static constexpr size_t STUN_BINDING_REQUEST_SIZE = 20;

typedef struct stun_transaction {
  /// 0 while the slot is free
  stun_handle_t handle;
  enum {
    /// Waiting to go out, or for the server's answer
    PENDING,
    BOUND,
    FAILED,
  } state;
  stun_transaction_id_t id;
  stun_retransmit_t retransmit;
  /// Once BOUND
  stun_socket_address_t mapped;
} stun_transaction_t;

struct stun_session {
  stun_config_t config;
  stun_handle_t last_handle;
  uint8_t outgoing_data[STUN_BINDING_REQUEST_SIZE];
  /// `config.capacity` of them, each kept until its last event is polled
  stun_transaction_t transactions[];
};

static void *stun_default_alloc(void * /*ctx*/, size_t size) {
  return malloc(size);
}

static void stun_default_free(void * /*ctx*/, void *ptr) { free(ptr); }

stun_session_t *stun_session_begin(stun_config_t config) {
  if (!config.allocator.alloc && !config.allocator.free) {
    config.allocator.alloc = stun_default_alloc;
    config.allocator.free = stun_default_free;
  }
  assert(config.allocator.alloc && config.allocator.free);
  assert(config.rng.fill);

  if (config.capacity == 0) {
    config.capacity = STUN_DEFAULT_CAPACITY;
  }

  stun_session_t *session =
      ALLOC(config.allocator, sizeof(stun_session_t) +
                                  config.capacity * sizeof(stun_transaction_t));
  if (session) {
    *session = (stun_session_t){.config = config};
    for (size_t i = 0; i < config.capacity; ++i) {
      session->transactions[i] = (stun_transaction_t){};
    }
  }

  return session;
}

void stun_session_end(stun_session_t *session) {
  assert(session);
  FREE(session->config.allocator, session);
}

static stun_transaction_t *stun_session_find(stun_session_t *session,
                                             stun_handle_t handle) {
  for (size_t i = 0; i < session->config.capacity; ++i) {
    if (session->transactions[i].handle == handle) {
      return &session->transactions[i];
    }
  }
  return nullptr;
}

// the next handle that isn't 0 or in use, which there is one of while a slot
// is free
static stun_handle_t stun_session_next_handle(stun_session_t *session) {
  do {
    session->last_handle += 1;
  } while (session->last_handle == 0 ||
           stun_session_find(session, session->last_handle));
  return session->last_handle;
}

stun_handle_or_error_t stun_session_binding_request(stun_session_t *session) {
  assert(session);

  auto const transaction = stun_session_find(session, 0);
  if (!transaction) {
    return (stun_handle_or_error_t){.has_value = false, .error = ENOBUFS};
  }

  stun_transaction_id_t id;
  if (!session->config.rng.fill(session->config.rng.ctx, sizeof(id.bytes),
                                id.bytes)) {
    return (stun_handle_or_error_t){.has_value = false, .error = EIO};
  }

  *transaction = (stun_transaction_t){
      .handle = stun_session_next_handle(session),
      .state = PENDING,
      .id = id,
  };
  return (stun_handle_or_error_t){.has_value = true,
                                  .value = transaction->handle};
}

// the event for a transaction that's done, which frees its slot
static stun_event_t stun_session_report(stun_transaction_t *transaction) {
  auto const event =
      transaction->state == BOUND
          ? (stun_event_t){.type = STUN_EVENT_BOUND,
                           .bound = {.handle = transaction->handle,
                                     .mapped = transaction->mapped}}
          : (stun_event_t){.type = STUN_EVENT_FAILED,
                           .failed = {.handle = transaction->handle}};
  *transaction = (stun_transaction_t){};
  return event;
}

stun_event_t stun_session_poll(stun_session_t *session, stun_time_ms_t now) {
  assert(session);

  stun_optional_time_ms_t deadline = {.has_value = false};
  for (size_t i = 0; i < session->config.capacity; ++i) {
    auto const transaction = &session->transactions[i];
    if (transaction->handle == 0) {
      continue;
    }
    if (transaction->state != PENDING) {
      return stun_session_report(transaction);
    }

    switch (stun_retransmit_poll(&transaction->retransmit, now)) {
    case STUN_RETRANSMIT_WAIT:
      if (!deadline.has_value ||
          transaction->retransmit.next < deadline.value) {
        deadline = (stun_optional_time_ms_t){
            .has_value = true,
            .value = transaction->retransmit.next,
        };
      }
      break;
    case STUN_RETRANSMIT_DUE: {
      auto const size = stun_message_write(
          (view_t){.size = sizeof(session->outgoing_data),
                   .data = session->outgoing_data},
          STUN_CLASS_REQUEST, STUN_METHOD_BINDING, &transaction->id);
      stun_retransmit_advance(&transaction->retransmit, now);
      return (stun_event_t){
          .type = STUN_EVENT_SEND,
          .send = {.size = size, .data = session->outgoing_data},
      };
    }
    case STUN_RETRANSMIT_GAVE_UP:
      transaction->state = FAILED;
      return stun_session_report(transaction);
    }
  }

  return (stun_event_t){.type = STUN_EVENT_TIMEOUT,
                        .timeout = {.deadline = deadline}};
}

static stun_transaction_t *
stun_session_find_pending(stun_session_t *session,
                          stun_message_t const *message) {
  for (size_t i = 0; i < session->config.capacity; ++i) {
    auto const transaction = &session->transactions[i];
    if (transaction->handle != 0 && transaction->state == PENDING &&
        memcmp(transaction->id.bytes, message->transaction_id.bytes,
               sizeof(transaction->id.bytes)) == 0) {
      return transaction;
    }
  }
  return nullptr;
}

// the first XOR-MAPPED-ADDRESS (section 14), unless there are
// comprehension-required attributes we don't know
static stun_optional_socket_address_t
stun_session_read_binding_response(stun_message_t const *message) {
  stun_optional_socket_address_t mapped = {.has_value = false};
  auto it = stun_message_attributes(message);
  stun_attribute_t attribute;
  while (stun_attribute_next(&it, &attribute)) {
    if (attribute.type == STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS) {
      if (!mapped.has_value) {
        mapped = stun_attribute_read_xor_mapped_address(
            &attribute, &message->transaction_id);
        if (!mapped.has_value) {
          return mapped;
        }
      }
    } else if (stun_attribute_is_comprehension_required(attribute.type)) {
      return (stun_optional_socket_address_t){.has_value = false};
    }
  }
  return mapped;
}

void stun_session_on_datagram(stun_session_t *session,
                              size_t size,
                              uint8_t const data[]) {
  assert(session);
  assert(data);

  auto const parsed =
      stun_message_parse((const_view_t){.size = size, .data = data});
  if (!parsed.has_value) {
    return;
  }
  auto const message = &parsed.value;
  if (message->message_class != STUN_CLASS_SUCCESS ||
      message->method != STUN_METHOD_BINDING) {
    return;
  }

  // a late answer to a retransmission finds its transaction done or gone
  auto const transaction = stun_session_find_pending(session, message);
  if (!transaction) {
    return;
  }

  auto const mapped = stun_session_read_binding_response(message);
  if (mapped.has_value) {
    transaction->state = BOUND;
    transaction->mapped = mapped.value;
  }
}
