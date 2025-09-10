use crate::common::{
    constants::responses::MOCK_REFRESH_TOKEN,
    helper::{
        assert_successful_begin_register_response, assert_successful_finish_login_response,
        assert_successful_finish_register_response, assert_successful_logout_response,
        assert_successful_refresh_response, create_auth_service, create_begin_request,
        create_login_finish_request, create_register_finish_request,
        get_begin_login_error_test_cases, get_begin_register_error_test_cases,
        get_finish_login_error_test_cases, get_finish_register_error_test_cases,
        get_logout_test_cases, get_refresh_error_test_cases, run_begin_login_error_test_case,
        run_begin_register_error_test_case, run_finish_login_error_test_case,
        run_finish_register_error_test_case, run_logout_test_case, run_refresh_error_test_case,
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

    for test_case in &test_cases {
        println!("Running begin_register test case: {}", test_case.test_name);
        run_begin_register_error_test_case(test_case).await;
    }
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

    for test_case in &test_cases {
        println!("Running finish_register test case: {}", test_case.test_name);
        run_finish_register_error_test_case(test_case).await;
    }
}

#[tokio::test]
async fn begin_login_success() {
    let auth_service = create_auth_service();
    let request = create_begin_request();

    let result = auth_service.begin_register(request).await;
    assert_successful_begin_register_response(result);
}

#[tokio::test]
async fn begin_login_all_error_scenarios() {
    let test_cases = get_begin_login_error_test_cases();

    for test_case in &test_cases {
        println!("Running begin_login test case: {}", test_case.test_name);
        run_begin_login_error_test_case(test_case).await;
    }
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

    for test_case in &test_cases {
        println!("Running finish_login test case: {}", test_case.test_name);
        run_finish_login_error_test_case(test_case).await;
    }
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

    for test_case in &test_cases {
        println!("Running refresh test case: {}", test_case.test_name);
        run_refresh_error_test_case(test_case).await;
    }
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

    for test_case in &test_cases {
        println!("Running logout test case: {}", test_case.test_name);
        run_logout_test_case(test_case).await;
    }
}
