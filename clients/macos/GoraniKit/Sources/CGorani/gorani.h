/* Copyright 2026- Seongwoo Hong. All rights reserved. */

/* The macOS shell's bridge to the Rust client core (commit 39c,
   clients/macos/src/lib.rs). One JSON protocol (the replica's — see
   clients/core/src/replica.rs › dispatch); every string returned here is
   freed with gorani_free. A session may be called from any thread. */

#ifndef GORANI_H
#define GORANI_H

#include <stdbool.h>

typedef struct GoraniSession GoraniSession;

/* The area the profile names (case_id NULL: the member's own), unlocked
   with this computer's enrolled copy. NULL on failure, *error set. */
GoraniSession *gorani_open(const char *profile, const char *case_id, const char *dev_email, bool accept_unverified, char **error);

/* The in-memory twin: tests, and a demo without a server. */
GoraniSession *gorani_open_memory(const char *area);

/* One request, one answer — both JSON. */
char *gorani_call(GoraniSession *session, const char *request_json);

void gorani_free(char *s);
void gorani_close(GoraniSession *session);

#endif
