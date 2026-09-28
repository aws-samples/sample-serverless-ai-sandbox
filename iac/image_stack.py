# kiro-classification: public
"""`ImageStack`: the Sandbox_Runtime MicroVM image version (R15.3, R11.7).

The ``lambda-microvms`` service model is not yet available in boto3, so no automated image build is
possible through a programmatic path. Instead, the stack reads the published image version from CDK
context (``imageVersion``) and exposes it as :attr:`ImageStack.image_version`, which is what
`ControlPlaneStack` threads into `OrchestratorSettings.image_ref`.

When no ``imageVersion`` is provided, the stack emits a synthesis warning and uses a placeholder
string, so the operator sees the gap on first deploy rather than at runtime.
"""

from __future__ import annotations

from typing import Any, Final

import aws_cdk as cdk
from constructs import Construct

from control_plane.allocation.tags import TENANT_TAG_KEY
from control_plane.tenancy import require_tenant_id

__all__ = [
    "DEFAULT_IMAGE_TENANT_ID",
    "IMAGE_VERSION_CONTEXT_KEY",
    "PLACEHOLDER_IMAGE_VERSION",
    "ImageStack",
]

#: The CDK context key for the published image version.
IMAGE_VERSION_CONTEXT_KEY: Final = "imageVersion"

#: The Tenant an image belongs to when the operator names none. One image serves the whole
#: deployment: under ``single-tenant`` the operator is the Tenant, and under ``multi-tenant`` the
#: image is shared across Tenants, so the owner R11.7 asks for is the operator either way.
DEFAULT_IMAGE_TENANT_ID: Final = "operator"

#: The placeholder used when no ``imageVersion`` is in CDK context.
PLACEHOLDER_IMAGE_VERSION: Final = "PLACEHOLDER-build-image-via-console"


class ImageStack(cdk.Stack):
    """Reads the published MicroVM image version from CDK context and tags it with a Tenant."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        image_tenant_id: str = DEFAULT_IMAGE_TENANT_ID,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        #: Validated by the module that validates every other Tenant identifier, so an image tag
        #: and a partition key cannot disagree about what a legal identifier is.
        self.image_tenant_id = require_tenant_id(image_tenant_id)
        #: R11.7's tag, keyed from ``control_plane.allocation.tags``, the sole owner of the
        #: spelling. There is no Session tag: an image has no Session.
        self.image_tags: dict[str, str] = {TENANT_TAG_KEY: self.image_tenant_id}

        self._image_version = self.node.try_get_context(IMAGE_VERSION_CONTEXT_KEY) or ""
        if not self._image_version:
            cdk.Annotations.of(self).add_warning(
                "No imageVersion in CDK context. Build the MicroVM image via the AWS Console "
                "and redeploy with: cdk deploy -c imageVersion=<version>"
            )
            self._image_version = PLACEHOLDER_IMAGE_VERSION

    @property
    def image_version(self) -> str:
        """The published image version, which becomes ``OrchestratorSettings.image_ref``."""
        return self._image_version
