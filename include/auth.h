// gtklock
// Copyright (c) 2022 Jovan Lanik

// PAM Authentication

#pragma once

#include <glib.h>
#include <sys/types.h>

enum pwcheck {
	PW_WAIT,
	PW_FAILURE,
	PW_SUCCESS,
	PW_ERROR,
	PW_MESSAGE,
};

enum pipedir {
	PIPE_PARENT,
	PIPE_CHILD,
	PIPE_LAST,
};

typedef int pipe_t[PIPE_LAST];

struct auth_session {
	pipe_t err_pipe;
	pipe_t out_pipe;
	pid_t pid;
	char *error_string;
	char *message_string;
};

void auth_session_init(struct auth_session *session);
void auth_session_free(struct auth_session *session);
char *auth_session_get_error(struct auth_session *session);
char *auth_session_get_message(struct auth_session *session);
enum pwcheck auth_session_check(struct auth_session *session, const char *service, const char *s);
char *auth_get_error(void);
char *auth_get_message(void);
enum pwcheck auth_pw_check(const char *s);
