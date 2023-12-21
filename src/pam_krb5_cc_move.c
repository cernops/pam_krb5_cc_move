//   Copyright 2024 CERN
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <pwd.h>
#include <krb5/krb5.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>

#define DEBUG_LOG_LEVEL LOG_DEBUG

// Function to replace %{uid} with the actual UID
void replaceSubstring(char *str, const char *search, const char *replace) {
    char *ptr = strstr(str, search);

    while (ptr != NULL) {
        int searchLen = strlen(search);
        int replaceLen = strlen(replace);
        int tailLen = strlen(ptr + searchLen);

        memmove(ptr + replaceLen, ptr + searchLen, tailLen + 1);
        memcpy(ptr, replace, replaceLen);

        ptr = strstr(ptr + replaceLen, search);
    }
}

// Function to parse options with equal signs
void parseOptions(const char **argv, const char **source, const char **destination, int *debug) {

    for (int i = 0; argv[i] != NULL; ++i) {
        if (strncmp(argv[i], "source=", 7) == 0) {
            *source = &argv[i][7];
        } else if (strncmp(argv[i], "destination=", 12) == 0) {
            *destination = &argv[i][12];
        } else if (strcmp(argv[i], "debug") == 0) {
            *debug = 1;
        }
    }
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *pam_user;
    struct passwd *pwd;
    krb5_context context;
    krb5_principal principal;
    krb5_ccache keyring_cache;
    int ret;

    int debug = 0;
    const char *source = "KEYRING:persistent:%{uid}";
    const char *destination = "FILE:/run/user/%{uid}/krb5cc";

    // Parse options
    parseOptions(argv, &source, &destination, &debug);

    if (debug) {
        pam_syslog(pamh, DEBUG_LOG_LEVEL, "Debug mode enabled");
    }

    // Get the PAM_USER (user being authenticated)
    ret = pam_get_user(pamh, &pam_user, NULL);
    if (ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Error getting PAM_USER: %s", pam_strerror(pamh, ret));
        return PAM_SESSION_ERR;
    }

    // Get user information using getpwnam
    pwd = getpwnam(pam_user);
    if (pwd == NULL) {
        pam_syslog(pamh, LOG_ERR, "Error getting user information for PAM_USER: %s", pam_user);
        return PAM_SESSION_ERR;
    }
    char uidstr[20];
    sprintf(uidstr, "%d", pwd->pw_uid);

    // Fork as the user and do the migration
    if (debug) {
        pam_syslog(pamh, DEBUG_LOG_LEVEL, "Starting fork as uid %d", pwd->pw_uid);
    }

    pid_t child_pid;
    child_pid = fork();
    if (child_pid == -1) {
        // Fork failed
        pam_syslog(pamh, LOG_ERR, "Fork failed");
        return PAM_AUTH_ERR;
    }

    if (child_pid == 0) {
        ret = setgid(pwd->pw_gid);
        if (ret != 0) {
            pam_syslog(pamh, LOG_ERR, "Error calling setgid to %d", pwd->pw_gid);
            exit(EXIT_FAILURE);
        }

        ret = setgroups(1, &pwd->pw_gid);
        if (ret != 0) {
            pam_syslog(pamh, LOG_ERR, "Error calling setgroups to %d", pwd->pw_gid);
            exit(EXIT_FAILURE);
        }

        ret = setuid(pwd->pw_uid);
        if (ret != 0) {
            pam_syslog(pamh, LOG_ERR, "Error calling setuid to %d", pwd->pw_uid);
            exit(EXIT_FAILURE);
        }

        if (debug) {
            pam_syslog(pamh, DEBUG_LOG_LEVEL, "Forked off as user %d", pwd->pw_uid);
        }

        // Initialize Kerberos context
        ret = krb5_init_context(&context);
        if (ret != 0) {
            pam_syslog(pamh, LOG_ERR, "Error initializing Kerberos context: %s", krb5_get_error_message(context, ret));
            exit(EXIT_FAILURE);
        }

        // Construct KEYRING cache name with UID
        char keyring_cache_name[1024];
        snprintf(keyring_cache_name, sizeof(keyring_cache_name), "%s", source);
        replaceSubstring(keyring_cache_name, "%{uid}", uidstr);

        if (debug) {
            pam_syslog(pamh, DEBUG_LOG_LEVEL, "Source Credential Cache %s", keyring_cache_name);
        }

        // Open KEYRING cache
        ret = krb5_cc_resolve(context, keyring_cache_name, &keyring_cache);
        if (ret != 0) {
            pam_syslog(pamh, LOG_ERR, "Error resolving KEYRING cache: %s", krb5_get_error_message(context, ret));
            krb5_free_context(context);
            exit(EXIT_FAILURE);
        }

        // Get principal from KEYRING cache
        ret = krb5_cc_get_principal(context, keyring_cache, &principal);
        if (ret != 0) {
            pam_syslog(pamh, LOG_INFO, "No delegate kerberos principal in KEYRING cache: %s", krb5_get_error_message(context, ret));
            krb5_cc_close(context, keyring_cache);
            krb5_free_context(context);
            exit(EXIT_SUCCESS);
        }

        // Log the principal name
        char *principal_name = NULL;
        krb5_unparse_name(context, principal, &principal_name);
        if (debug) {
            pam_syslog(pamh, DEBUG_LOG_LEVEL, "Principal name: %s", principal_name);
        }
        free(principal_name);

        // Specify the path for the cache
        char file_cache_name[PATH_MAX];
        snprintf(file_cache_name, sizeof(file_cache_name), "%s", destination);
        replaceSubstring(file_cache_name, "%{uid}", uidstr);

        // Resolve and initialize the cache
        krb5_ccache file_cache;
        ret = krb5_cc_resolve(context, file_cache_name, &file_cache);
        if (ret == KRB5_FCC_NOFILE) {
            // If the cache file doesn't exist, initialize a new cache
            ret = krb5_cc_initialize(context, file_cache, principal);
            if (ret != 0) {
                pam_syslog(pamh, LOG_ERR, "Error initializing cache: %s", krb5_get_error_message(context, ret));
                krb5_free_principal(context, principal);
                krb5_free_context(context);
                exit(EXIT_FAILURE);
            }
        } else if (ret != 0) {
            pam_syslog(pamh, LOG_ERR, "Error resolving cache: %s", krb5_get_error_message(context, ret));
            krb5_free_principal(context, principal);
            krb5_free_context(context);
            exit(EXIT_FAILURE);
        }

        if (debug) {
            pam_syslog(pamh, DEBUG_LOG_LEVEL, "File Cache Initialized at %s", file_cache_name);
        }

        // Move credentials from KCM to file cache
        ret = krb5_cc_move(context, keyring_cache, file_cache);
        if (ret != 0) {
            pam_syslog(pamh, LOG_ERR, "Error moving credentials from KCM to file cache: %s", krb5_get_error_message(context, ret));
            krb5_cc_close(context, keyring_cache);
            krb5_cc_close(context, file_cache);
            krb5_free_principal(context, principal);
            krb5_free_context(context);
            exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
    } else {
        int status;
        if (waitpid(child_pid, &status, 0) == -1) {
            pam_syslog(pamh, LOG_ERR, "Wait failed");
            exit(EXIT_FAILURE);
        }

        if (WIFEXITED(status)) {
            if (debug) {
                pam_syslog(pamh, DEBUG_LOG_LEVEL, "Child process exited with status %d", WEXITSTATUS(status));
            }
        } else {
            pam_syslog(pamh, LOG_ERR, "Child processes exited badly %d", WEXITSTATUS(status));
            return PAM_SESSION_ERR;
        }
    }

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Perform any cleanup if necessary
    return PAM_SUCCESS;
}
