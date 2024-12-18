

# The User Management System Final Project

## Docker Hub URL [Click Here](https://hub.docker.com/repository/docker/bb472/user_management_project/general)

## Issues and Fixes

## Issue 1

**Issue:** Email verification in user creation

**Details:** The issue details are following :

1. **Format Validation of Email:** The `EmailStr` type from `Pydantic` class ensures the email is in a valid format (e.g., test@domain. com). But, using patterns like `admin` is not restricted.
2. **Configurable Domains:** There is no dynamic use of a set of domains from email providers.
3. **Consistent Checking:** Converts usernames and domains into lowercase, but does not check consistently.
4. **Error Handing:** There is no such handing of errors with actionable feedback if validation fails.

**Code Fix:** [Click Here](https://github.com/kaw393939/user_management/commit/602ee9e8062e0b939c59e908fc2f1f93d88dd885)

## Issue 2

**Issue:** Password verification in user creation

**Details:** The issue details are following:

1. **Ensuring Password Length:** There is no validation present for password length which should be at least 8 characters long.
2. **Requirement of Uppercase, Lowercase, Digits and Special Characters:** There is no validation present for the condition if passwords have uppercase letters (A-Z), lowercase letters (a-z), numerical digits (0-9) and special characters (!@#$%^&*(),.?\":{}|<>).

**Code Fix:** [Click Here](https://github.com/kaw393939/user_management/commit/287df460a451c14afd7cfb769f01ef4f0f7ca260)

## Issue 3

**Issue:** Validate Nickname

**Details:** The issue details are following :

1.	**Valid Nickname Usage:** There is no validation to allow nicknames using characters, underscores, or hyphens.
2.	**Length Validation:** Both minimum and maximum lengths are not declared.

**Code Fix:** [Click Here](https://github.com/kaw393939/user_management/commit/54db2a4412356e2841db39fa18cfac323a0b4ddd)

## Issue 4

**Issue:** Validate URLs and Profile Picture

**Details:** The issue details are following:

1.	**URL validation:** `HttpUrl` has not been used in all URLs.
2.	**Validate Image File Format in Profile Picture:** The image file is not restricted to commonly used picture formats.


**Code Fix:** [Click Here](https://github.com/kaw393939/user_management/commit/a5c809428db2d94cf909301a0df47374879f5c52)

## Issue 5

**Issue:** Issues in Email Service

**Details:** The issue details are following :

1.	**Synchronous Call inside Asynchronous Method:** Inside the `send_user_email` async method, the send email is called synchronously. 
2.	**Exceptions are not handled in Email Service:** During rendering and sending emails, exceptions are not handled in `send_user_email` method.

**Code Fix:** [Click Here](https://github.com/kaw393939/user_management/commit/fd2dab81582a28496b56c3ea49e03061daf9bb62)
