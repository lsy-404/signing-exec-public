# Signing executor

Fixed macOS and Windows recipes for the central signing service. Inputs and results use the authenticated runner API. The center verifies the repository, immutable recipe tag, commit, workflow run, token and request nonce.

macOS uses the `signing` environment. Windows uses `signing-windows`, its separate runner token and an Azure workload identity limited to the approved certificate profile. Restrict deployments to the approved recipe tag.
