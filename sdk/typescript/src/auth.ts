// kiro-classification: public
/**
 * Authentication strategies for the Control Plane API.
 *
 * Two modes:
 * - **SigV4**: signs requests with the caller's current AWS credentials.
 *   Requires `@aws-sdk/client-sts` and related packages — not bundled.
 * - **Bearer token**: attaches `Authorization: Bearer <token>` for multi-tenant
 *   deployments that use a Lambda authorizer instead of `AWS_IAM`.
 */

/** Authentication strategy applied to outgoing Control Plane requests. */
export interface Auth {
  apply(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: Uint8Array | null,
  ): Promise<Record<string, string>>;
}

/** Service name used for SigV4 signing against API Gateway. */
const SERVICE_NAME = 'execute-api';

/**
 * Signs requests using AWS SigV4.
 *
 * This is a stub — the TypeScript SDK does not bundle `@aws-sdk/signature-v4`.
 * Install `@aws-sdk/client-sts` and related packages, or use {@link BearerAuth}
 * for multi-tenant deployments.
 */
export class SigV4Auth implements Auth {
  readonly #region: string;

  constructor(region: string) {
    this.#region = region;
  }

  get region(): string {
    return this.#region;
  }

  async apply(
    _method: string,
    _url: string,
    _headers: Record<string, string>,
    _body?: Uint8Array | null,
  ): Promise<Record<string, string>> {
    throw new Error(
      'SigV4Auth requires @aws-sdk/client-sts and @smithy/signature-v4. ' +
        'Install those packages and provide a custom Auth implementation, or use BearerAuth.',
    );
  }
}

/**
 * Attaches a bearer token for multi-tenant deployments.
 */
export class BearerAuth implements Auth {
  readonly #token: string;

  constructor(token: string) {
    this.#token = token;
  }

  async apply(
    _method: string,
    _url: string,
    headers: Record<string, string>,
    _body?: Uint8Array | null,
  ): Promise<Record<string, string>> {
    return { ...headers, Authorization: `Bearer ${this.#token}` };
  }
}
