#include <byo/stun/stun.h>

#include "message.h"
#include "retransmit.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC(allocator, ...) (allocator.alloc(allocator.ctx, __VA_ARGS__))
#define FREE(allocator, ...) (allocator.free(allocator.ctx, __VA_ARGS__))

static constexpr uint16_t DEFAULT_CAPACITY = 8;

// a Binding request without attributes is just the header
static constexpr size_t BINDING_REQUEST_SIZE = 20;

typedef struct transaction {
  /// 0 while the slot is free
  stun_handle_t handle;
  enum {
    /// Waiting to go out, or for the server's answer
    PENDING,
    SUCCEEDED,
    FAILED,
  } state;
  stun_transaction_id_t id;
  stun_retransmit_t retransmit;
  /// Once SUCCEEDED
  stun_socket_address_t mapped;
  /// Once FAILED
  stun_failure_t failure;
  /// Once FAILED with STUN_FAILURE_ERROR_RESPONSE
  uint16_t error_code;
} transaction_t;

struct stun_agent {
  stun_config_t config;
  stun_handle_t last_handle;
  uint8_t outgoing_data[BINDING_REQUEST_SIZE];
  /// `config.capacity` of them, each kept until its last event is polled
  transaction_t transactions[];
};

static void *default_alloc(void * /*ctx*/, size_t size) { return malloc(size); }

static void default_free(void * /*ctx*/, void *ptr) { free(ptr); }

stun_agent_t *stun_agent_begin(stun_config_t config) {
  if (!config.allocator.alloc && !config.allocator.free) {
    config.allocator.alloc = default_alloc;
    config.allocator.free = default_free;
  }
  assert(config.allocator.alloc && config.allocator.free);
  assert(config.rng.fill);

  if (config.capacity == 0) {
    config.capacity = DEFAULT_CAPACITY;
  }

  stun_agent_t *agent =
      ALLOC(config.allocator,
            sizeof(stun_agent_t) + config.capacity * sizeof(transaction_t));
  if (agent) {
    *agent = (stun_agent_t){.config = config};
    for (size_t i = 0; i < config.capacity; ++i) {
      agent->transactions[i] = (transaction_t){};
    }
  }

  return agent;
}

void stun_agent_end(stun_agent_t *agent) {
  assert(agent);
  FREE(agent->config.allocator, agent);
}

static transaction_t *find_transaction(stun_agent_t *agent,
                                       stun_handle_t handle) {
  for (size_t i = 0; i < agent->config.capacity; ++i) {
    if (agent->transactions[i].handle == handle) {
      return &agent->transactions[i];
    }
  }
  return nullptr;
}

// the next handle that isn't 0 or in use, which there is one of while a slot
// is free
static stun_handle_t next_handle(stun_agent_t *agent) {
  do {
    agent->last_handle += 1;
  } while (agent->last_handle == 0 ||
           find_transaction(agent, agent->last_handle));
  return agent->last_handle;
}

stun_handle_or_error_t stun_agent_binding_request(stun_agent_t *agent) {
  assert(agent);

  auto const transaction = find_transaction(agent, 0);
  if (!transaction) {
    return (stun_handle_or_error_t){.has_value = false, .error = ENOBUFS};
  }

  stun_transaction_id_t id;
  if (!agent->config.rng.fill(agent->config.rng.ctx, sizeof(id.bytes),
                              id.bytes)) {
    return (stun_handle_or_error_t){.has_value = false, .error = EIO};
  }

  *transaction = (transaction_t){
      .handle = next_handle(agent),
      .state = PENDING,
      .id = id,
  };
  return (stun_handle_or_error_t){.has_value = true,
                                  .value = transaction->handle};
}

// the event for a transaction that's done, which frees its slot
static stun_event_t report(transaction_t *transaction) {
  auto const event =
      transaction->state == SUCCEEDED
          ? (stun_event_t){.type = STUN_EVENT_BOUND,
                           .bound = {.handle = transaction->handle,
                                     .mapped = transaction->mapped}}
          : (stun_event_t){.type = STUN_EVENT_FAILED,
                           .failed = {.handle = transaction->handle,
                                      .reason = transaction->failure,
                                      .error_code = transaction->error_code}};
  *transaction = (transaction_t){};
  return event;
}

static void fail(transaction_t *transaction, stun_failure_t failure) {
  transaction->state = FAILED;
  transaction->failure = failure;
}

stun_event_t stun_agent_poll(stun_agent_t *agent, stun_time_ms_t now) {
  assert(agent);

  stun_optional_time_ms_t deadline = {.has_value = false};
  for (size_t i = 0; i < agent->config.capacity; ++i) {
    auto const transaction = &agent->transactions[i];
    if (transaction->handle == 0) {
      continue;
    }

    if (transaction->state != PENDING) {
      return report(transaction);
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
          (view_t){.size = sizeof(agent->outgoing_data),
                   .data = agent->outgoing_data},
          STUN_CLASS_REQUEST, STUN_METHOD_BINDING, &transaction->id);
      stun_retransmit_advance(&transaction->retransmit, now);
      return (stun_event_t){
          .type = STUN_EVENT_SEND,
          .send = {.size = size, .data = agent->outgoing_data},
      };
    }
    case STUN_RETRANSMIT_GAVE_UP:
      fail(transaction, STUN_FAILURE_TIMEOUT);
      return report(transaction);
    }
  }

  return (stun_event_t){.type = STUN_EVENT_TIMEOUT,
                        .timeout = {.deadline = deadline}};
}

// by transaction ID alone, since every request is a Binding request
static transaction_t *find_pending(stun_agent_t *agent,
                                   stun_header_t const *header) {
  for (size_t i = 0; i < agent->config.capacity; ++i) {
    auto const transaction = &agent->transactions[i];
    if (transaction->handle != 0 && transaction->state == PENDING &&
        memcmp(transaction->id.bytes, header->transaction_id.bytes,
               sizeof(transaction->id.bytes)) == 0) {
      return transaction;
    }
  }
  return nullptr;
}

static void apply_response(transaction_t *transaction,
                           stun_message_t const *message) {
  // parsing checked that the response carries what its class and method
  // call for
  switch (message->header.message_class) {
  case STUN_CLASS_ERROR: {
    // whatever the method
    auto const error =
        stun_message_find_attribute(message, STUN_ATTRIBUTE_ERROR_CODE);
    assert(error.has_value);
    fail(transaction, STUN_FAILURE_ERROR_RESPONSE);
    transaction->error_code = error.value.error_code;
    break;
  }
  case STUN_CLASS_SUCCESS: {
    // what a success carries depends on the method, and only Binding
    // responses get this far
    assert(message->header.method == STUN_METHOD_BINDING);
    auto const address =
        stun_message_find_attribute(message, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS);
    assert(address.has_value);
    transaction->state = SUCCEEDED;
    transaction->mapped = address.value.xor_mapped_address;
    break;
  }
  case STUN_CLASS_REQUEST:
  case STUN_CLASS_INDICATION:
    // only responses get this far
    assert(false);
    break;
  }
}

void stun_agent_on_datagram(stun_agent_t *agent,
                            size_t size,
                            uint8_t const data[]) {
  assert(agent);
  assert(data);

  auto const parsed =
      stun_message_parse((const_view_t){.size = size, .data = data});
  if (parsed.status == STUN_MESSAGE_PARSE_NOT_STUN) {
    return;
  }

  // only responses answer our requests, and every request is a Binding
  // request
  auto const header = &parsed.header;
  if ((header->message_class != STUN_CLASS_SUCCESS &&
       header->message_class != STUN_CLASS_ERROR) ||
      header->method != STUN_METHOD_BINDING) {
    return;
  }

  // a late answer to a retransmission finds its transaction done or gone
  auto const transaction = find_pending(agent, header);
  if (!transaction) {
    return;
  }

  if (parsed.status == STUN_MESSAGE_PARSE_VALID) {
    apply_response(transaction, &parsed.message);
  } else {
    fail(transaction, STUN_FAILURE_INVALID_RESPONSE);
  }
}
