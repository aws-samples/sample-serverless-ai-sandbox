# kiro-classification: public
#
# The explicit Compute_Provider registry and the isolation allowlist (R5.6).
#
# Two properties of this module are the point of it, and both are deliberate refusals:
#
#   1. **No dynamic discovery.** The registry is a module-level dict populated by explicit
#      `register` calls made from explicit imports in the Control_Plane package. There is no
#      entry-point scan, no directory walk and no import hook, so the set of providers a
#      deployment can use is auditable by reading source rather than by running it.
#   2. **Isolation is not a runtime capability flag.** `ProviderCapabilities` carries no
#      "strongly isolated" field a weaker backend could set to `true`. Instead the name of
#      every provider fit to hold Untrusted_Code is listed in `ISOLATION_APPROVED`, and
#      `register` refuses anything absent from it. Isolation strength is therefore a
#      deployment decision made in this file, not a claim a provider makes about itself.
#
# The two non-isolation providers the design writes to prove the seam is not Lambda-shaped,
# `local-firecracker` and `fargate-task`, are deliberately absent from the allowlist. They are
# constructed directly by the test suite and by conformance exercises; they cannot be
# registered, which is exactly the guarantee that keeps them away from Untrusted_Code.

from control_plane.providers.base import ComputeProvider

__all__ = [
    "ISOLATION_APPROVED",
    "REGISTRY",
    "get",
    "register",
    "registered_names",
]

# The providers a deployment has admitted, keyed by `ComputeProvider.name`.
REGISTRY: dict[str, ComputeProvider] = {}

# The names approved as an isolation boundary for Untrusted_Code. Adding a name here is a
# reviewed change to this file, which is what makes the decision auditable.
#
# Lambda Managed Instances, including its GPU beta, is absent and stays absent: a GPU_Target
# is reached from inside a Sandbox through the Egress_Controller (R5.10), so it never needs to
# be an isolation boundary.
ISOLATION_APPROVED: frozenset[str] = frozenset({"lambda-microvm"})


def register(provider: ComputeProvider) -> None:
    """Admit a provider to this deployment's registry.

    Args:
        provider: the provider to admit, identified by its own `name`.

    Raises:
        ValueError: `provider.name` is not in `ISOLATION_APPROVED`.
    """
    if provider.name not in ISOLATION_APPROVED:
        raise ValueError(f"{provider.name} is not approved as an isolation boundary")
    REGISTRY[provider.name] = provider


def get(name: str) -> ComputeProvider:
    """Return the registered provider a deployment configuration names.

    The provider for a Session is selected from deployment configuration and recorded on the
    Session row at creation (R6.6). No Client_SDK parameter names a provider and no Client_SDK
    code branches on one (R5.6).

    Args:
        name: the provider name held in deployment configuration.

    Raises:
        LookupError: no provider by that name has been registered. The message names the
            providers that were registered, because the usual cause is a missing explicit
            import rather than a wrong configuration value.
    """
    try:
        return REGISTRY[name]
    except KeyError:
        registered = ", ".join(registered_names()) or "none"
        raise LookupError(
            f"no Compute_Provider named {name!r} is registered (registered: {registered})"
        ) from None


def registered_names() -> tuple[str, ...]:
    """Return the names of every registered provider, sorted."""
    return tuple(sorted(REGISTRY))
