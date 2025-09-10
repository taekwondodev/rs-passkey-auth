macro_rules! run_test_cases {
    ($test_cases:expr, $test_name:expr, $test_runner:expr) => {
        for test_case in &$test_cases {
            println!("Running {} test case: {}", $test_name, test_case.test_name);
            $test_runner(test_case).await;
        }
    };
}

use crate::common::{
    constants::responses::MOCK_REFRESH_TOKEN,
    helper::{
        assert_successful_begin_login_response, assert_successful_begin_register_response,
        assert_successful_finish_login_response, assert_successful_finish_register_response,
        assert_successful_healthy_response, assert_successful_logout_response,
        assert_successful_refresh_response, assert_unhealthy_health_response, create_auth_service,
        create_auth_service_both_unhealthy, create_auth_service_db_unhealthy,
        create_auth_service_redis_unhealthy, create_begin_request, create_login_finish_request,
        create_register_finish_request, get_begin_login_error_test_cases,
        get_begin_register_error_test_cases, get_finish_login_error_test_cases,
        get_finish_register_error_test_cases, get_logout_test_cases, get_refresh_error_test_cases,
        run_begin_login_error_test_case, run_begin_register_error_test_case,
        run_finish_login_error_test_case, run_finish_register_error_test_case,
        run_logout_test_case, run_refresh_error_test_case,
    },
};

#[tokio::test]
async fn begin_register_success() {
    let auth_service = create_auth_service();
    let request = create_begin_request();

    let result = auth_service.begin_register(request).await;
    assert_successful_begin_register_response(result);
}

#[tokio::test]
async fn begin_register_all_error_scenarios() {
    let test_cases = get_begin_register_error_test_cases();
    run_test_cases!(
        test_cases,
        "begin_register",
        run_begin_register_error_test_case
    );
}

#[tokio::test]
async fn finish_register_success() {
    let auth_service = create_auth_service();
    let request = create_register_finish_request();

    let result = auth_service.finish_register(request).await;
    assert_successful_finish_register_response(result);
}

#[tokio::test]
async fn finish_register_all_error_scenarios() {
    let test_cases = get_finish_register_error_test_cases();
    run_test_cases!(
        test_cases,
        "finish_register",
        run_finish_register_error_test_case
    );
}

#[tokio::test]
async fn begin_login_success() {
    let auth_service = create_auth_service();
    let request = create_begin_request();

    let result = auth_service.begin_login(request).await;
    assert_successful_begin_login_response(result);
}

#[tokio::test]
async fn begin_login_all_error_scenarios() {
    let test_cases = get_begin_login_error_test_cases();
    run_test_cases!(test_cases, "begin_login", run_begin_login_error_test_case);
}

#[tokio::test]
async fn finish_login_success() {
    let auth_service = create_auth_service();
    let request = create_login_finish_request();

    let result = auth_service.finish_login(request).await;
    assert_successful_finish_login_response(result);
}

#[tokio::test]
async fn finish_login_all_error_scenarios() {
    let test_cases = get_finish_login_error_test_cases();
    run_test_cases!(test_cases, "finish_login", run_finish_login_error_test_case);
}

#[tokio::test]
async fn refresh_success() {
    let auth_service = create_auth_service();

    let result = auth_service.refresh(MOCK_REFRESH_TOKEN).await;
    assert_successful_refresh_response(result);
}

#[tokio::test]
async fn refresh_all_error_scenarios() {
    let test_cases = get_refresh_error_test_cases();
    run_test_cases!(test_cases, "refresh", run_refresh_error_test_case);
}

#[tokio::test]
async fn logout_success() {
    let auth_service = create_auth_service();

    let result = auth_service.logout(MOCK_REFRESH_TOKEN).await;
    assert_successful_logout_response(result);
}

#[tokio::test]
async fn logout_all_error_scenarios() {
    let test_cases = get_logout_test_cases();
    run_test_cases!(test_cases, "logout", run_logout_test_case);
}

#[tokio::test]
async fn check_health_success() {
    let auth_service = create_auth_service();

    let result = auth_service.check_health().await;
    assert_successful_healthy_response(result);
}

#[tokio::test]
async fn check_all_unhealthy_scenarios() {
    let test_scenarios = vec![
        (create_auth_service_db_unhealthy(), "Database"),
        (create_auth_service_redis_unhealthy(), "Redis"),
        (
            create_auth_service_both_unhealthy(),
            "services are unhealthy",
        ),
    ];

    for (auth_service, expected_error_msg) in test_scenarios {
        let result = auth_service.check_health().await;
        assert_unhealthy_health_response(result, expected_error_msg);
    }
}
