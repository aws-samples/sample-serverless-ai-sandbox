# kiro-classification: public
"""The Compute_Provider seam and the providers this deployment admits (R5.6).

This module is the single admission site. The registry is populated here, by an explicit
import and an explicit `register` call, so the set of providers a deployment can use is
auditable by reading this file rather than by running the process. There is no entry-point
scan, no directory walk and no import hook.

Only `lambda-microvm` is admitted, because it is the only name in `ISOLATION_APPROVED`.
`local-firecracker` and `fargate-task` are deliberately absent: they are constructed directly
by the test suite and by conformance exercises, and `register` refuses them, which is what
keeps them away from Untrusted_Code.

A deployment that wants the published Region memory ceiling in `limits().capacity_limit`
re-registers a provider configured with its own quota code; `register` keys on the provider
name, so the later call replaces this default.
"""

from control_plane.providers.lambda_microvm import LambdaMicroVmProvider
from control_plane.providers.registry import register

register(LambdaMicroVmProvider())
