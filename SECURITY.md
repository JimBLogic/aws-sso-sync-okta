# Security policy

## Reporting

Do not publish live Okta tokens, IAM Identity Center SCIM tokens, SSM values, tenant domains, user email lists, group membership data or AWS account identifiers in a public issue.

Use GitHub private vulnerability reporting when available, or contact the repository owner through the methods shown on the GitHub profile.

A useful report includes the affected revision, impact, safe reproduction steps with dummy tenants, and a proposed remediation when known.

## Credential exposure

If an Okta token or SCIM token is committed, logged or otherwise disclosed:

1. revoke or rotate it immediately;
2. inspect Okta, AWS and CloudTrail-related audit data for unexpected use;
3. replace the corresponding SSM `SecureString` value;
4. remove the secret from Git history, not only the latest revision;
5. review caches, forks, workflow artifacts and external mirrors.

## Identity safety

Test changes against disposable or non-production tenants first. Run without `--apply`, review the plan, and only then execute the exact reviewed command with `--apply`.

This utility intentionally does not implement deletion, disabling or membership removal. Changes that add deprovisioning require an explicit design review, independent tests and a rollback strategy.
