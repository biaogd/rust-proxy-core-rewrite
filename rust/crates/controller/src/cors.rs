use super::{
    AllowHeaders, AllowMethods, AllowOrigin, ControllerState, CorsLayer, Duration, HeaderValue,
    Layer, Method, Next, Request, Response, Service, State, StatusCode, empty_response, header,
};

pub(super) async fn apply_dynamic_cors(
    State(state): State<ControllerState>,
    mut request: Request,
    next: Next,
) -> Response {
    let preflight = is_preflight(&request);
    if preflight && !valid_preflight_contract(&request) {
        return denied_preflight_response();
    }
    if preflight {
        normalize_preflight_request(&mut request);
    }
    let cors = cors_layer(&state.current_config().controller_cors);
    let mut service = cors.layer(next);
    let mut response = match service.call(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };
    normalize_cors_vary(&mut response, preflight);
    response
}

pub(super) fn normalize_preflight_request(request: &mut Request) {
    if let Some(method) = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_uppercase)
        .and_then(|value| HeaderValue::from_str(&value).ok())
    {
        request
            .headers_mut()
            .insert(header::ACCESS_CONTROL_REQUEST_METHOD, method);
    }
    let headers = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .filter_map(|name| match name.trim().to_ascii_lowercase().as_str() {
                    "authorization" => Some("Authorization"),
                    "content-type" => Some("Content-Type"),
                    "origin" => Some("Origin"),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(", ")
        });
    match headers {
        Some(headers) if !headers.is_empty() => {
            if let Ok(headers) = HeaderValue::from_str(&headers) {
                request
                    .headers_mut()
                    .insert(header::ACCESS_CONTROL_REQUEST_HEADERS, headers);
            }
        }
        _ => {
            request
                .headers_mut()
                .remove(header::ACCESS_CONTROL_REQUEST_HEADERS);
        }
    }
}

pub(super) fn is_preflight(request: &Request) -> bool {
    request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
        && request.headers().contains_key(header::ORIGIN)
}

pub(super) fn valid_preflight_contract(request: &Request) -> bool {
    let method = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return false;
    }
    request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|headers| {
            headers
                .split(',')
                .filter(|name| !name.trim().is_empty())
                .all(|name| {
                    matches!(
                        name.trim().to_ascii_lowercase().as_str(),
                        "content-type" | "authorization" | "origin"
                    )
                })
        })
}

pub(super) fn denied_preflight_response() -> Response {
    let mut response = empty_response(StatusCode::OK);
    normalize_cors_vary(&mut response, true);
    response
}

pub(super) fn normalize_cors_vary(response: &mut Response, preflight: bool) {
    response.headers_mut().remove(header::VARY);
    let values = if preflight {
        &[
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
        ][..]
    } else {
        &["Origin"][..]
    };
    for value in values {
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static(value));
    }
}

pub(super) fn cors_layer(config: &rewrite_config::ControllerCors) -> CorsLayer {
    let origins = config
        .allow_origins
        .iter()
        .map(|origin| origin.to_lowercase())
        .collect::<Vec<_>>();
    let allow_origin = if origins.is_empty() || origins.iter().any(|origin| origin == "*") {
        AllowOrigin::any()
    } else {
        AllowOrigin::predicate(move |origin, _| {
            let Ok(origin) = origin.to_str() else {
                return false;
            };
            let origin = origin.to_lowercase();
            origins
                .iter()
                .any(|allowed| wildcard_origin_matches(allowed, &origin))
        })
    };
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request())
        .allow_private_network(config.allow_private_network)
        .max_age(Duration::from_mins(5))
}

pub(super) fn wildcard_origin_matches(allowed: &str, origin: &str) -> bool {
    allowed.split_once('*').map_or_else(
        || allowed == origin,
        |(prefix, suffix)| origin.starts_with(prefix) && origin.ends_with(suffix),
    )
}
