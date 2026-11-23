/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "active_responses.h"
#include "firewall_helpers.h"

firewall_result_t try_iproute2(const char *srcip, int action, int ip_version, const char *argv0);

static bool binary_available;
static int lock_result;
static int command_result;
static int lock_releases;
static char captured_args[6][64];

firewall_result_t __wrap_check_binary_available(const char *binary_name, char **path_out,
                                                 const char *log_prefix) {
    assert_string_equal(binary_name, "ip");
    if (!binary_available) {
        return FIREWALL_NOT_AVAILABLE;
    }

    *path_out = strdup("/usr/sbin/ip");
    assert_non_null(*path_out);
    return FIREWALL_SUCCESS;
}

int __wrap_acquire_ar_lock(lock_context_t *ctx) {
    return lock_result;
}

void __wrap_release_ar_lock(lock_context_t *ctx) {
    lock_releases++;
}

int __wrap_execute_command_with_retry(const char *ar_name, const char *path, char * const *argv) {
    assert_string_equal(path, "/usr/sbin/ip");
    memset(captured_args, 0, sizeof(captured_args));

    for (size_t i = 0; i < 6 && argv[i] != NULL; i++) {
        snprintf(captured_args[i], sizeof(captured_args[i]), "%s", argv[i]);
    }

    return command_result;
}

static int test_setup(void **state) {
    binary_available = true;
    lock_result = OS_SUCCESS;
    command_result = OS_SUCCESS;
    lock_releases = 0;
    memset(captured_args, 0, sizeof(captured_args));
    return 0;
}

void test_iproute2_enable_ipv4_uses_blackhole_route(void **state) {
    assert_int_equal(try_iproute2("192.0.2.10", ENABLE_COMMAND, 4, "block-ip"), FIREWALL_SUCCESS);
    assert_string_equal(captured_args[0], "/usr/sbin/ip");
    assert_string_equal(captured_args[1], "-4");
    assert_string_equal(captured_args[2], "route");
    assert_string_equal(captured_args[3], "add");
    assert_string_equal(captured_args[4], "blackhole");
    assert_string_equal(captured_args[5], "192.0.2.10");
    assert_int_equal(lock_releases, 1);
}

void test_iproute2_disable_ipv6_removes_blackhole_route(void **state) {
    assert_int_equal(try_iproute2("2001:db8::10", DISABLE_COMMAND, 6, "block-ip"), FIREWALL_SUCCESS);
    assert_string_equal(captured_args[0], "/usr/sbin/ip");
    assert_string_equal(captured_args[1], "-6");
    assert_string_equal(captured_args[2], "route");
    assert_string_equal(captured_args[3], "del");
    assert_string_equal(captured_args[4], "blackhole");
    assert_string_equal(captured_args[5], "2001:db8::10");
    assert_int_equal(lock_releases, 1);
}

void test_iproute2_missing_binary_is_not_available(void **state) {
    binary_available = false;
    assert_int_equal(try_iproute2("192.0.2.10", ENABLE_COMMAND, 4, "block-ip"), FIREWALL_NOT_AVAILABLE);
    assert_int_equal(lock_releases, 0);
    assert_string_equal(captured_args[0], "");
}

void test_iproute2_command_failure_releases_lock(void **state) {
    command_result = OS_INVALID;
    assert_int_equal(try_iproute2("192.0.2.10", ENABLE_COMMAND, 4, "block-ip"), FIREWALL_EXECUTION_FAILED);
    assert_int_equal(lock_releases, 1);
}

void test_iproute2_lock_failure_does_not_execute_command(void **state) {
    lock_result = OS_INVALID;
    assert_int_equal(try_iproute2("192.0.2.10", ENABLE_COMMAND, 4, "block-ip"), FIREWALL_EXECUTION_FAILED);
    assert_int_equal(lock_releases, 0);
    assert_string_equal(captured_args[0], "");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_iproute2_enable_ipv4_uses_blackhole_route, test_setup),
        cmocka_unit_test_setup(test_iproute2_disable_ipv6_removes_blackhole_route, test_setup),
        cmocka_unit_test_setup(test_iproute2_missing_binary_is_not_available, test_setup),
        cmocka_unit_test_setup(test_iproute2_command_failure_releases_lock, test_setup),
        cmocka_unit_test_setup(test_iproute2_lock_failure_does_not_execute_command, test_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
