// gtklock
// Copyright (c) 2022 Jovan Lanik, Zephyr Lykos

// PAM Authentication

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <security/pam_appl.h>

#include "auth.h"

struct conv_data {
	const char *pw;
	int *err;
	int *out;
};

static struct auth_session default_session = { .pid = -2 };

char *auth_get_error(void) {
	return auth_session_get_error(&default_session);
}
char *auth_get_message(void) {
	return auth_session_get_message(&default_session);
}

void auth_session_init(struct auth_session *session) {
	session->pid = -2;
	session->error_string = NULL;
	session->message_string = NULL;
}

void auth_session_free(struct auth_session *session) {
	if(session->error_string) {
		free(session->error_string);
		session->error_string = NULL;
	}
	if(session->message_string) {
		free(session->message_string);
		session->message_string = NULL;
	}

	if(session->pid >= 0) {
		close(session->err_pipe[PIPE_PARENT]);
		close(session->out_pipe[PIPE_PARENT]);
	}
	session->pid = -2;
}

char *auth_session_get_error(struct auth_session *session) {
	char *s = session->error_string;
	session->error_string = NULL;
	return s;
}

char *auth_session_get_message(struct auth_session *session) {
	char *s = session->message_string;
	session->message_string = NULL;
	return s;
}

static void send_msg(const char *msg, int fd) {
	size_t len = strlen(msg);
	write(fd, &len, sizeof(size_t));
	write(fd, msg, len);
}

static int conversation(
	int num_msg,
	const struct pam_message **msg,
	struct pam_response **resp,
	void *appdata_ptr
) {
	struct conv_data *data = appdata_ptr;
	*resp = calloc(num_msg, sizeof(struct pam_response));
	if(*resp == NULL) {
		g_warning("Failed allocation");
		return PAM_ABORT;
	}

	for(int i = 0; i < num_msg; ++i) {
		resp[i]->resp_retcode = 0;
		switch(msg[i]->msg_style) {
			case PAM_PROMPT_ECHO_OFF:
			case PAM_PROMPT_ECHO_ON:
				resp[i]->resp = strdup(data->pw);
				if(resp[i]->resp == NULL) {
					g_warning("Failed allocation");
					return PAM_ABORT;
				}
				break;
			case PAM_ERROR_MSG:
				send_msg(msg[i]->msg, data->err[1]);
				break;
			case PAM_TEXT_INFO:
				send_msg(msg[i]->msg, data->out[1]);
				break;
		}
	}
	return PAM_SUCCESS;
}

static void auth_child(const char *service, const char *s, int *err, int *out) {
	struct passwd *pwd = NULL;

	errno = 0;
	pwd = getpwuid(getuid());
	if(pwd == NULL) {
		perror("getpwnam");
		exit(EXIT_FAILURE);
	}

	char *username = pwd->pw_name;
	int pam_status;
	struct pam_handle *handle;
	struct conv_data data = { .pw = s, .err = err, .out = out };
	struct pam_conv conv = { conversation, (void *)&data };
	pam_status = pam_start(service, username, &conv, &handle);
	if(pam_status != PAM_SUCCESS) {
		fprintf(stderr, "pam_start() failed");
		exit(EXIT_FAILURE);
	}

	int ret = pam_authenticate((pam_handle_t *)handle, 0);
	pam_status = ret;
	pam_status = pam_setcred((pam_handle_t *)handle, PAM_REFRESH_CRED);
	if(pam_end(handle, pam_status) != PAM_SUCCESS)
		fprintf(stderr, "pam_end() failed");
	if(ret == PAM_SUCCESS) exit(EXIT_SUCCESS);
	exit(EXIT_FAILURE);
}

enum pwcheck auth_session_check(struct auth_session *session, const char *service, const char *s) {
	if(session->pid < 0) {
		if(pipe(session->err_pipe) != 0) {
			g_warning("err pipe failure");
			return PW_WAIT;
		}
		if(pipe(session->out_pipe) != 0) {
			close(session->err_pipe[PIPE_PARENT]);
			close(session->err_pipe[PIPE_CHILD]);
			g_warning("out pipe failure");
			return PW_WAIT;
		}
		session->pid = fork();
		if(session->pid == -1) {
			close(session->err_pipe[PIPE_PARENT]);
			close(session->err_pipe[PIPE_CHILD]);
			close(session->out_pipe[PIPE_PARENT]);
			close(session->out_pipe[PIPE_CHILD]);
			g_warning("fork failure");
			return PW_WAIT;
		}
		else if(session->pid == 0) {
			prctl(PR_SET_PDEATHSIG, SIGTERM);
			if(getppid() == 1) exit(EXIT_FAILURE);
			close(session->err_pipe[PIPE_PARENT]);
			close(session->out_pipe[PIPE_PARENT]);
			freopen("/dev/null", "r", stdin);
			auth_child(service, s, session->err_pipe, session->out_pipe);
		}
		close(session->err_pipe[PIPE_CHILD]);
		close(session->out_pipe[PIPE_CHILD]);
		fcntl(session->err_pipe[PIPE_PARENT], F_SETFL, O_NONBLOCK);
		fcntl(session->out_pipe[PIPE_PARENT], F_SETFL, O_NONBLOCK);
	}

	if(session->error_string) free(session->error_string);
	if(session->message_string) free(session->message_string);

	size_t len;
	ssize_t nread;
	nread = read(session->err_pipe[PIPE_PARENT], &len, sizeof(size_t));
	if(nread > 0 && len <= PAM_MAX_MSG_SIZE) {
		session->error_string = malloc(PAM_MAX_MSG_SIZE);
		nread = read(session->err_pipe[PIPE_PARENT], session->error_string, len);
		session->error_string[nread] = '\0';
		return PW_ERROR;
	}
	nread = read(session->out_pipe[PIPE_PARENT], &len, sizeof(size_t));
	if(nread > 0 && len <= PAM_MAX_MSG_SIZE) {
		session->message_string = malloc(PAM_MAX_MSG_SIZE);
		nread = read(session->out_pipe[PIPE_PARENT], session->message_string, len);
		session->message_string[nread] = '\0';
		return PW_MESSAGE;
	}

	int status;
	if(waitpid(session->pid, &status, WNOHANG) > 0 && WIFEXITED(status)) {
		close(session->err_pipe[PIPE_PARENT]);
		close(session->out_pipe[PIPE_PARENT]);
		session->pid = -2;
		if(WEXITSTATUS(status) == EXIT_SUCCESS) return PW_SUCCESS;
		else return PW_FAILURE;
	}
	return PW_WAIT;
}

enum pwcheck auth_pw_check(const char *s) {
	return auth_session_check(&default_session, "gtklock", s);
}
