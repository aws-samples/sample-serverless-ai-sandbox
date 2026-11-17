// kiro-classification: public
/**
 * Authentication strategies for the Control Plane API.
 *
 * Two modes:
 * - **SigV4**: signs requests with the caller's current AWS credentials (resolved from the
 *   standard Node provider chain). Used by single-tenant deployments whose API uses `AWS_IAM`.
 * - **Bearer token**: attaches `Authorization: Bearer <token>` for multi-tenant
 *   deployments that use a Lambda authorizer instead of `AWS_IAM`.
 */

import { SignatureV4 } from '@smithy/signature-v4';
import { Hash } from '@smithy/hash-node';
import { HttpRequest } from '@smithy/protocol-http';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';

/** Authentication strategy applied to outgoing Control Plane requests. */
export interface Auth {
  apply(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: Uint8Array | null,
  ): Promise<Record<string, string>>;
}

/**
 * Signs Control Plane requests with AWS SigV4 for `execute-api`.
 *
 * Credentials come from the standard Node provider chain (environment, shared config/credentials,
 * SSO, container, and IMDS), mirroring the Python SDK's reliance on botocore's default resolution.
 */
export class SigV4Auth implements Auth {
  readonly #region: string;
  #signer: SignatureV4 | null = null;

  constructor(region: string) {
    this.#region = region;
  }

  get region(): string {
    return this.#region;
  }

  #getSigner(): SignatureV4 {
    if (this.#signer === null) {
      this.#signer = new SignatureV4({
        service: 'execute-api',
        region: this.#region,
        credentials: fromNodeProviderChain(),
        sha256: Hash.bind(null, 'sha256'),
      });
    }
    return this.#signer;
  }

  async apply(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: Uint8Array | null,
  ): Promise<Record<string, string>> {
    const parsed = new URL(url);
    const request = new HttpRequest({
      method,
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port ? Number(parsed.port) : undefined,
      path: parsed.pathname,
      query: Object.fromEntries(parsed.searchParams.entries()),
      headers: { ...headers, host: parsed.host },
      body: body ?? undefined,
    });
    const signed = await this.#getSigner().sign(request);
    return signed.headers;
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
