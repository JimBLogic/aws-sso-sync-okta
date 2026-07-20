# aws-sso-sync-okta

A defensive Python utility for synchronizing selected Okta groups into **AWS IAM Identity Center** through the AWS SCIM endpoint.

The command is **dry-run by default**. It only creates missing users, creates missing groups and adds missing memberships when `--apply` is supplied. It never deletes, disables or removes identities.

> Prefer Okta's supported SCIM provisioning integration whenever it is available for your plan and architecture. This repository is a small bridge and learning project, not an official AWS or Okta product.

## Security model

- Okta and AWS SCIM tokens are read from AWS Systems Manager Parameter Store.
- Tokens are never accepted as command-line arguments.
- AWS authentication uses the normal SDK credential chain, ideally temporary credentials from a narrowly scoped IAM role.
- Running with the AWS account root user is explicitly unsupported and unnecessary.
- Group names must match Okta exactly.
- HTTP calls have timeouts and fail on non-success status codes.
- Okta and SCIM pagination are handled.
- Email addresses and group names are hashed in logs unless `--show-identifiers` is intentionally enabled.
- Mutating operations require `--apply`.

## Scope

The synchronizer can:

1. read selected Okta groups and their users;
2. find corresponding users and groups in IAM Identity Center;
3. create missing users;
4. create missing groups;
5. add missing group memberships.

It does **not** update attributes, disable users, remove memberships or delete resources. Deprovisioning deserves a separate, heavily reviewed workflow.

## Requirements

- Python 3.10+
- an Okta API token with only the read permissions required for groups and users;
- an IAM Identity Center SCIM endpoint and access token;
- an AWS role or federated session allowed to read only the required SSM parameters;
- network access to Okta and the AWS SCIM endpoint.

AWS documentation:

- IAM Identity Center SCIM provisioning: https://docs.aws.amazon.com/singlesignon/latest/userguide/provision-automatically.html
- Enable automatic provisioning: https://docs.aws.amazon.com/singlesignon/latest/userguide/how-to-with-scim.html
- IAM security best practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Configuration

Store the following parameters in AWS Systems Manager Parameter Store. Use `SecureString` for both tokens and restrict access to the exact parameter ARNs.

| Parameter | Type | Purpose |
| --- | --- | --- |
| `/aws-sso-sync-okta/groups` | `String` | Comma-separated exact Okta group names |
| `/aws-sso-sync-okta/okta-api-token` | `SecureString` | Okta API token |
| `/aws-sso-sync-okta/scim-access-token` | `SecureString` | IAM Identity Center SCIM access token |

Do not paste tokens into shell history, source code, screenshots, issues or CI logs. Create and rotate them through a controlled administrative workflow.

Set the non-secret endpoints:

```bash
export OKTA_DOMAIN="example.okta.com"
export AWS_SCIM_BASE_URL="https://scim.eu-west-1.amazonaws.com/example/scim/v2"
export AWS_REGION="eu-west-1"
```

The SCIM URL must be copied from IAM Identity Center and must end in `/scim/v2`.

## Least-privilege AWS access

The process does not need administrator or root credentials. Its AWS SDK access is only used to read the configured SSM parameters.

A starting policy should restrict `ssm:GetParameter` to those exact parameters:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": [
        "arn:aws:ssm:REGION:ACCOUNT_ID:parameter/aws-sso-sync-okta/groups",
        "arn:aws:ssm:REGION:ACCOUNT_ID:parameter/aws-sso-sync-okta/okta-api-token",
        "arn:aws:ssm:REGION:ACCOUNT_ID:parameter/aws-sso-sync-okta/scim-access-token"
      ]
    }
  ]
}
```

When the `SecureString` parameters use a customer-managed KMS key, add narrowly scoped `kms:Decrypt` permission for that key and constrain it to SSM where practical.

## Usage

### Preview one group

```bash
python sync.py --group "security-analysts"
```

### Preview several groups

```bash
python sync.py \
  --group "security-analysts" \
  --group "incident-response"
```

### Use the group list stored in SSM

```bash
python sync.py
```

### Apply reviewed changes

```bash
python sync.py --group "security-analysts" --apply
```

Always run the dry-run first, review the counts and identifiers, and then repeat the same command with `--apply`.

## Useful options

```text
--aws-profile PROFILE          Use a named local AWS profile
--aws-region REGION            Select the SSM region
--groups-parameter NAME        Override the SSM group-list parameter
--okta-token-parameter NAME    Override the Okta token parameter
--scim-token-parameter NAME    Override the SCIM token parameter
--timeout SECONDS              Set the HTTP timeout
--show-identifiers             Show real emails and group names in logs
--verbose                      Enable debug logging
--apply                        Perform writes
```

## Token lifecycle

IAM Identity Center SCIM access tokens expire and should be monitored and rotated before expiry. Rotate both Okta and SCIM tokens immediately if they are exposed, and remember that deleting a secret from the latest commit does not remove it from Git history.

## Testing

```bash
python -m py_compile sync.py tests/test_sync.py
python -m unittest discover -s tests -v
```

The unit tests cover validation and privacy controls. End-to-end testing requires disposable Okta and IAM Identity Center test tenants; do not test destructive identity workflows against production first.

## License

GPL-3.0. See `LICENSE.md`.
