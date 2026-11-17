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
  /// Once FAILED
  stun_failure_t failure;
  /// Once FAILED with STUN_FAILURE_ERROR_RESPONSE
  uint16_t error_code;
} stun_transaction_t;

struct stun_agent {
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

stun_agent_t *stun_agent_begin(stun_config_t config) {
  if (!config.allocator.alloc && !config.allocator.free) {
    config.allocator.alloc = stun_default_alloc;
    config.allocator.free = stun_default_free;
  }
  assert(config.allocator.alloc && config.allocator.free);
  assert(config.rng.fill);

  if (config.capacity == 0) {
    config.capacity = STUN_DEFAULT_CAPACITY;
  }

  stun_agent_t *agent =
      ALLOC(config.allocator, sizeof(stun_agent_t) +
                                  config.capacity * sizeof(stun_transaction_t));
  if (agent) {
    *agent = (stun_agent_t){.config = config};
    for (size_t i = 0; i < config.capacity; ++i) {
      agent->transactions[i] = (stun_transaction_t){};
    }
  }

  return agent;
}

void stun_agent_end(stun_agent_t *agent) {
  assert(agent);
  FREE(agent->config.allocator, agent);
}

static stun_transaction_t *stun_agent_find(stun_agent_t *agent,
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
static stun_handle_t stun_agent_next_handle(stun_agent_t *agent) {
  do {
    agent->last_handle += 1;
  } while (agent->last_handle == 0 ||
           stun_agent_find(agent, agent->last_handle));
  return agent->last_handle;
}

stun_handle_or_error_t stun_agent_binding_request(stun_agent_t *agent) {
  assert(agent);

  auto const transaction = stun_agent_find(agent, 0);
  if (!transaction) {
    return (stun_handle_or_error_t){.has_value = false, .error = ENOBUFS};
  }

  stun_transaction_id_t id;
  if (!agent->config.rng.fill(agent->config.rng.ctx, sizeof(id.bytes),
                              id.bytes)) {
    return (stun_handle_or_error_t){.has_value = false, .error = EIO};
  }

  *transaction = (stun_transaction_t){
      .handle = stun_agent_next_handle(agent),
      .state = PENDING,
      .id = id,
  };
  return (stun_handle_or_error_t){.has_value = true,
                                  .value = transaction->handle};
}

// the event for a transaction that's done, which frees its slot
static stun_event_t stun_agent_report(stun_transaction_t *transaction) {
  auto const event =
      transaction->state == BOUND
          ? (stun_event_t){.type = STUN_EVENT_BOUND,
                           .bound = {.handle = transaction->handle,
                                     .mapped = transaction->mapped}}
          : (stun_event_t){.type = STUN_EVENT_FAILED,
                           .failed = {.handle = transaction->handle,
                                      .reason = transaction->failure,
                                      .error_code = transaction->error_code}};
  *transaction = (stun_transaction_t){};
  return event;
}

static void stun_agent_fail(stun_transaction_t *transaction,
                            stun_failure_t failure) {
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
      return stun_agent_report(transaction);
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
      stun_agent_fail(transaction, STUN_FAILURE_TIMEOUT);
      return stun_agent_report(transaction);
    }
  }

  return (stun_event_t){.type = STUN_EVENT_TIMEOUT,
                        .timeout = {.deadline = deadline}};
}

static stun_transaction_t *
stun_agent_find_pending(stun_agent_t *agent, stun_message_t const *message) {
  for (size_t i = 0; i < agent->config.capacity; ++i) {
    auto const transaction = &agent->transactions[i];
    if (transaction->handle != 0 && transaction->state == PENDING &&
        memcmp(transaction->id.bytes, message->transaction_id.bytes,
               sizeof(transaction->id.bytes)) == 0) {
      return transaction;
    }
  }
  return nullptr;
}

// the first attribute of `type`, unless the message has other
// comprehension-required attributes, which we don't know
static bool stun_agent_find_attribute(stun_message_t const *message,
                                      uint16_t type,
                                      stun_attribute_t *found) {
  bool has_found = false;
  auto it = stun_message_attributes(message);
  stun_attribute_t attribute;
  while (stun_attribute_next(&it, &attribute)) {
    if (attribute.type == type) {
      if (!has_found) {
        *found = attribute;
        has_found = true;
      }
    } else if (stun_attribute_is_comprehension_required(attribute.type)) {
      return false;
    }
  }
  return has_found;
}

void stun_agent_on_datagram(stun_agent_t *agent,
                            size_t size,
                            uint8_t const data[]) {
  assert(agent);
  assert(data);

  auto const parsed =
      stun_message_parse((const_view_t){.size = size, .data = data});
  if (!parsed.has_value) {
    return;
  }
  auto const message = &parsed.value;
  if ((message->message_class != STUN_CLASS_SUCCESS &&
       message->message_class != STUN_CLASS_ERROR) ||
      message->method != STUN_METHOD_BINDING) {
    return;
  }

  // a late answer to a retransmission finds its transaction done or gone
  auto const transaction = stun_agent_find_pending(agent, message);
  if (!transaction) {
    return;
  }

  stun_attribute_t attribute;
  if (message->message_class == STUN_CLASS_SUCCESS) {
    auto const mapped =
        stun_agent_find_attribute(message, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
                                  &attribute)
            ? stun_attribute_read_xor_mapped_address(&attribute,
                                                     &message->transaction_id)
            : (stun_optional_socket_address_t){.has_value = false};
    if (mapped.has_value) {
      transaction->state = BOUND;
      transaction->mapped = mapped.value;
      return;
    }
  } else {
    auto const error_code =
        stun_agent_find_attribute(message, STUN_ATTRIBUTE_ERROR_CODE,
                                  &attribute)
            ? stun_attribute_read_error_code(&attribute)
            : (stun_optional_error_code_t){.has_value = false};
    if (error_code.has_value) {
      stun_agent_fail(transaction, STUN_FAILURE_ERROR_RESPONSE);
      transaction->error_code = error_code.value;
      return;
    }
  }
  stun_agent_fail(transaction, STUN_FAILURE_INVALID_RESPONSE);
}
