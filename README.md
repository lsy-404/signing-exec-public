# macOS signing executor

Fixed signing recipes for the central signing service. Requests use a restricted environment token and a task nonce. The center verifies the repository, recipe tag, commit and complete GitHub run before accepting output.

Store `SIGNING_RUNNER_TOKEN` in the `signing` environment and restrict deployments to the approved immutable recipe tag. Apple credentials are released by the center only after input checks.
