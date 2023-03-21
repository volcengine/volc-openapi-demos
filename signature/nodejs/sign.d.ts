/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import * as crypto from 'crypto';
import { URLSearchParams } from "url";
import * as Buffer from "buffer";
export interface SignParams {
    /**
     * OpenAPI URL path
     * @default /
     */
    pathName?: string;
    /**
     * 请求 headers
     */
    headers: Record<string, string>;
    /**
     * 需要参与签算的 header keys
     * @default x-date、host
     */
    needSignHeaderKeys?: string[];
    /**
     * OpenAPI region
     * @example cn-north-1
     */
    region: string;
    /**
     * OpenAPI service name
     * @example ecs
     */
    serviceName: string;
    /**
     * OpenAPI AccessKey
     */
    accessKeyId: string;
    /**
     * OpenAPI SecretKey
     */
    secretAccessKey: string;
    /**
     * HTTP Request Method
     */
    method: string;
    /**
     * body
     */
    bodySha?: string;
    /**
     * HTTP request query object
     */
    query: Record<string, string | string[]>;
}
export declare function sign(params: SignParams): string;
export declare function hmac(secret: crypto.BinaryLike | crypto.KeyObject, s: string): Buffer.Buffer;
export declare function hash(s: string): string;
export declare function queryParamsToString(params: Record<string, undefined | null | string | string[]>): string;
export declare function getSignHeaders(originHeaders: SignParams['headers'], needSignHeaders?: string[]): [string, string];
export declare function uriEscape(str: string): string;
export declare function getDateTimeNow(): string;
export declare function getBodySha(body: Buffer | string | URLSearchParams): string;
