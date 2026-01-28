## 2026-01-28 - Open Redirect in Login
**Vulnerability:** The login route blindly followed the `next` parameter, allowing attackers to construct URLs that redirect users to malicious sites after successful authentication.
**Learning:** Logic vulnerabilities like Open Redirect are not automatically handled by frameworks and require explicit validation of the destination URL.
**Prevention:** Implement an `is_safe_url` helper that checks `url_parse(target).netloc` matches the application's host or is empty (relative path).
