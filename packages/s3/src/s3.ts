// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata, Value } from "@wiredwp/robinpath";
import { createHmac, createHash } from "node:crypto";

// ─── AWS Signature V4 internals ───────────────────────────────────────────────

interface S3Config {
  region: string;
  endpoint?: string;
  forcePathStyle?: boolean;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

const configs = new Map<string, S3Config>();

function getConfig(profile?: string): S3Config {
  const key = profile ?? "__default__";
  const cfg = configs.get(key);
  if (!cfg) throw new Error(`S3 client not configured. Call configure() first${profile ? ` for profile "${profile}"` : ""}.`);
  return cfg;
}

function sha256(data: string | Buffer | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmacSha256(key: string | Buffer, data: string): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

function getSigningKey(secretKey: string, dateStamp: string, region: string, service: string): Buffer {
  const kDate = hmacSha256(`AWS4${secretKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  return hmacSha256(kService, "aws4_request");
}

/** URI-encode per AWS rules (RFC 3986, but '/' is NOT encoded for path segments) */
function uriEncode(str: string, encodeSlash: boolean): string {
  let encoded = "";
  for (const ch of str) {
    if (
      (ch >= "A" && ch <= "Z") ||
      (ch >= "a" && ch <= "z") ||
      (ch >= "0" && ch <= "9") ||
      ch === "_" ||
      ch === "-" ||
      ch === "~" ||
      ch === "."
    ) {
      encoded += ch;
    } else if (ch === "/" && !encodeSlash) {
      encoded += ch;
    } else {
      const bytes = Buffer.from(ch, "utf8");
      for (const b of bytes) encoded += `%${b.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return encoded;
}

interface SignedRequestInit {
  method: string;
  path: string;        // e.g. "/" or "/bucket/key"
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string | Buffer | Uint8Array;
  config: S3Config;
  service?: string;
  /** If true, payload hash is UNSIGNED-PAYLOAD (for presigned URLs) */
  unsignedPayload?: boolean;
}

function buildUrl(config: S3Config, path: string, query?: Record<string, string>): string {
  let base: string;
  if (config.endpoint) {
    base = config.endpoint.replace(/\/+$/, "");
  } else {
    base = `https://s3.${config.region}.amazonaws.com`;
  }
  let url = `${base}${path}`;
  if (query && Object.keys(query).length > 0) {
    const qs = Object.entries(query)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${uriEncode(k, true)}=${uriEncode(v, true)}`)
      .join("&");
    url += `?${qs}`;
  }
  return url;
}

function hostFromConfig(config: S3Config): string {
  if (config.endpoint) {
    const u = new URL(config.endpoint);
    return u.host;
  }
  return `s3.${config.region}.amazonaws.com`;
}

function signRequest(opts: SignedRequestInit): { url: string; headers: Record<string, string> } {
  const { method, path, query = {}, config, unsignedPayload } = opts;
  const service = opts.service ?? "s3";
  const body = opts.body ?? "";
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.slice(0, 8);
  const host = hostFromConfig(config);
  const payloadHash = unsignedPayload ? "UNSIGNED-PAYLOAD" : sha256(typeof body === "string" ? body : Buffer.from(body as any));

  // Build headers map
  const hdrs: Record<string, string> = {
    host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    ...(opts.headers ?? {}),
  };
  if (config.sessionToken) {
    hdrs["x-amz-security-token"] = config.sessionToken;
  }

  // Canonical headers (sorted, lowercased keys, trimmed values)
  const signedHeaderNames = Object.keys(hdrs).map((h) => h.toLowerCase()).sort();
  const canonicalHeaders = signedHeaderNames.map((h) => `${h}:${hdrs[Object.keys(hdrs).find((k) => k.toLowerCase() === h)!]!.trim()}`).join("\n") + "\n";
  const signedHeaders = signedHeaderNames.join(";");

  // Canonical query string
  const canonicalQs = Object.entries(query)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${uriEncode(k, true)}=${uriEncode(v, true)}`)
    .join("&");

  const canonicalUri = uriEncode(path, false);

  const canonicalRequest = [method, canonicalUri, canonicalQs, canonicalHeaders, signedHeaders, payloadHash].join("\n");

  const credentialScope = `${dateStamp}/${config.region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, sha256(canonicalRequest)].join("\n");

  const signingKey = getSigningKey(config.secretAccessKey, dateStamp, config.region, service);
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");

  const authorization = `AWS4-HMAC-SHA256 Credential=${config.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  // Build final headers (exclude 'host' since fetch sets it automatically)
  const finalHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(hdrs)) {
    if (k.toLowerCase() !== "host") finalHeaders[k] = v;
  }
  finalHeaders["Authorization"] = authorization;

  const url = buildUrl(config, path, Object.keys(query).length > 0 ? query : undefined);
  return { url, headers: finalHeaders };
}

/** Build a presigned URL (query-string auth) */
function buildPresignedUrl(opts: {
  method: string;
  path: string;
  config: S3Config;
  expiresIn: number;
  query?: Record<string, string>;
  headers?: Record<string, string>;
}): string {
  const { method, path, config, expiresIn, headers: extraHeaders } = opts;
  const service = "s3";
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.slice(0, 8);
  const host = hostFromConfig(config);
  const credentialScope = `${dateStamp}/${config.region}/${service}/aws4_request`;

  const queryParams: Record<string, string> = {
    ...(opts.query ?? {}),
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": `${config.accessKeyId}/${credentialScope}`,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresIn),
    "X-Amz-SignedHeaders": "host",
  };
  if (config.sessionToken) {
    queryParams["X-Amz-Security-Token"] = config.sessionToken;
  }

  const canonicalQs = Object.entries(queryParams)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${uriEncode(k, true)}=${uriEncode(v, true)}`)
    .join("&");

  const canonicalUri = uriEncode(path, false);
  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = "host";
  const payloadHash = "UNSIGNED-PAYLOAD";

  const canonicalRequest = [method, canonicalUri, canonicalQs, canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, sha256(canonicalRequest)].join("\n");

  const signingKey = getSigningKey(config.secretAccessKey, dateStamp, config.region, service);
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");

  queryParams["X-Amz-Signature"] = signature;

  return buildUrl(config, path, queryParams);
}

// ─── S3 REST helpers ──────────────────────────────────────────────────────────

async function s3Fetch(opts: SignedRequestInit): Promise<Response> {
  const { url, headers } = signRequest(opts);
  const res = await fetch(url, {
    method: opts.method,
    headers,
    body: opts.body != null && opts.method !== "GET" && opts.method !== "HEAD" ? opts.body : undefined,
  });
  if (!res.ok && !(opts.method === "HEAD" && res.status === 404)) {
    const errBody = await res.text().catch(() => "");
    throw new Error(`S3 ${opts.method} ${opts.path} failed (${res.status}): ${errBody}`);
  }
  return res;
}

/** Minimal XML tag extractor — grabs text content of all <tag>…</tag> occurrences. */
function xmlTags(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "g");
  const results: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) results.push(m[1]);
  return results;
}

function xmlTag(xml: string, tag: string): string | undefined {
  const m = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`));
  return m?.[1];
}

function pathForBucketKey(bucket: string, key: string): string {
  return `/${bucket}/${key.replace(/^\/+/, "")}`;
}

// ─── Exported handlers ────────────────────────────────────────────────────────

export const S3Functions: Record<string, BuiltinHandler> = {
  configure: (args: Value[]) => {
    const options = args[0] as Record<string, unknown>;
    const profile = (options.profile as string) ?? undefined;
    const k = profile ?? "__default__";
    const cfg: S3Config = {
      region: (options.region as string) ?? "us-east-1",
      accessKeyId: options.accessKeyId as string,
      secretAccessKey: options.secretAccessKey as string,
      sessionToken: (options.sessionToken as string) ?? undefined,
      endpoint: (options.endpoint as string) ?? undefined,
      forcePathStyle: (options.forcePathStyle as boolean) ?? true,
    };
    if (!cfg.accessKeyId || !cfg.secretAccessKey) {
      throw new Error("accessKeyId and secretAccessKey are required");
    }
    configs.set(k, cfg);
    return { success: true, profile: k };
  },

  upload: async (args: Value[]) => {
    const bucket = args[0] as string;
    const key = args[1] as string;
    const body = args[2] as string | Buffer | Uint8Array;
    const options = (args[3] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    const headers: Record<string, string> = {};
    if (options.contentType) headers["content-type"] = options.contentType as string;
    if (options.metadata) {
      for (const [mk, mv] of Object.entries(options.metadata as Record<string, string>)) {
        headers[`x-amz-meta-${mk.toLowerCase()}`] = mv;
      }
    }
    const res = await s3Fetch({
      method: "PUT",
      path: pathForBucketKey(bucket, key),
      headers,
      body: typeof body === "string" ? body : body,
      config,
    });
    return { etag: res.headers.get("etag") ?? undefined, versionId: res.headers.get("x-amz-version-id") ?? undefined };
  },

  download: async (args: Value[]) => {
    const bucket = args[0] as string;
    const key = args[1] as string;
    const options = (args[2] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    const res = await s3Fetch({
      method: "GET",
      path: pathForBucketKey(bucket, key),
      config,
    });
    const buffer = Buffer.from(await res.arrayBuffer());
    if (options.encoding) return buffer.toString(options.encoding as BufferEncoding);
    return buffer;
  },

  remove: async (args: Value[]) => {
    const bucket = args[0] as string;
    const key = args[1] as string;
    const options = (args[2] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    await s3Fetch({
      method: "DELETE",
      path: pathForBucketKey(bucket, key),
      config,
    });
    return { success: true, bucket, key };
  },

  list: async (args: Value[]) => {
    const bucket = args[0] as string;
    const options = (args[1] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    const query: Record<string, string> = { "list-type": "2" };
    if (options.prefix) query["prefix"] = options.prefix as string;
    if (options.delimiter) query["delimiter"] = options.delimiter as string;
    if (options.maxKeys) query["max-keys"] = String(options.maxKeys);
    if (options.continuationToken) query["continuation-token"] = options.continuationToken as string;
    const res = await s3Fetch({
      method: "GET",
      path: `/${bucket}`,
      query,
      config,
    });
    const xml = await res.text();

    // Parse <Contents> blocks
    const contentsBlocks = xmlTags(xml, "Contents");
    const contents = contentsBlocks.map((block) => ({
      key: xmlTag(block, "Key"),
      size: xmlTag(block, "Size") ? Number(xmlTag(block, "Size")) : undefined,
      lastModified: xmlTag(block, "LastModified"),
      etag: xmlTag(block, "ETag"),
      storageClass: xmlTag(block, "StorageClass"),
    }));

    const commonPrefixes = xmlTags(xml, "CommonPrefixes").map((block) => xmlTag(block, "Prefix")).filter(Boolean) as string[];
    const isTruncated = xmlTag(xml, "IsTruncated") === "true";
    const nextContinuationToken = xmlTag(xml, "NextContinuationToken");

    return { contents, commonPrefixes, isTruncated, nextContinuationToken };
  },

  exists: async (args: Value[]) => {
    const bucket = args[0] as string;
    const key = args[1] as string;
    const options = (args[2] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    const { url, headers } = signRequest({
      method: "HEAD",
      path: pathForBucketKey(bucket, key),
      config,
    });
    const res = await fetch(url, { method: "HEAD", headers });
    if (res.ok) return true;
    if (res.status === 404) return false;
    throw new Error(`S3 HEAD ${bucket}/${key} failed (${res.status})`);
  },

  copy: async (args: Value[]) => {
    const sourceBucket = args[0] as string;
    const sourceKey = args[1] as string;
    const destBucket = args[2] as string;
    const destKey = args[3] as string;
    const options = (args[4] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    const res = await s3Fetch({
      method: "PUT",
      path: pathForBucketKey(destBucket, destKey),
      headers: {
        "x-amz-copy-source": `/${sourceBucket}/${sourceKey}`,
      },
      config,
    });
    const xml = await res.text();
    return {
      etag: xmlTag(xml, "ETag"),
      lastModified: xmlTag(xml, "LastModified"),
    };
  },

  move: async (args: Value[]) => {
    const sourceBucket = args[0] as string;
    const sourceKey = args[1] as string;
    const destBucket = args[2] as string;
    const destKey = args[3] as string;
    const options = (args[4] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    // Copy
    await s3Fetch({
      method: "PUT",
      path: pathForBucketKey(destBucket, destKey),
      headers: {
        "x-amz-copy-source": `/${sourceBucket}/${sourceKey}`,
      },
      config,
    });
    // Delete source
    await s3Fetch({
      method: "DELETE",
      path: pathForBucketKey(sourceBucket, sourceKey),
      config,
    });
    return { success: true, from: { bucket: sourceBucket, key: sourceKey }, to: { bucket: destBucket, key: destKey } };
  },

  presignUrl: async (args: Value[]) => {
    const bucket = args[0] as string;
    const key = args[1] as string;
    const options = (args[2] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    const expiresIn = (options.expiresIn as number) ?? 3600;
    const method = (options.method as string) ?? "GET";
    const extraHeaders: Record<string, string> = {};
    if (method === "PUT" && options.contentType) {
      extraHeaders["content-type"] = options.contentType as string;
    }
    const url = buildPresignedUrl({
      method,
      path: pathForBucketKey(bucket, key),
      config,
      expiresIn,
      headers: Object.keys(extraHeaders).length > 0 ? extraHeaders : undefined,
    });
    return { url, expiresIn };
  },

  createBucket: async (args: Value[]) => {
    const bucket = args[0] as string;
    const options = (args[1] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    // For us-east-1, no body needed; for other regions, need LocationConstraint
    let body: string | undefined;
    if (config.region && config.region !== "us-east-1") {
      body = `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>${config.region}</LocationConstraint></CreateBucketConfiguration>`;
    }
    await s3Fetch({
      method: "PUT",
      path: `/${bucket}`,
      body: body ?? "",
      config,
    });
    return { success: true, bucket };
  },

  deleteBucket: async (args: Value[]) => {
    const bucket = args[0] as string;
    const options = (args[1] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    await s3Fetch({
      method: "DELETE",
      path: `/${bucket}`,
      config,
    });
    return { success: true, bucket };
  },

  listBuckets: async (args: Value[]) => {
    const options = (args[0] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    const res = await s3Fetch({
      method: "GET",
      path: "/",
      config,
    });
    const xml = await res.text();
    const bucketBlocks = xmlTags(xml, "Bucket");
    return bucketBlocks.map((block) => ({
      name: xmlTag(block, "Name"),
      creationDate: xmlTag(block, "CreationDate"),
    }));
  },

  getMetadata: async (args: Value[]) => {
    const bucket = args[0] as string;
    const key = args[1] as string;
    const options = (args[2] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    const { url, headers } = signRequest({
      method: "HEAD",
      path: pathForBucketKey(bucket, key),
      config,
    });
    const res = await fetch(url, { method: "HEAD", headers });
    if (!res.ok) throw new Error(`S3 HEAD ${bucket}/${key} failed (${res.status})`);
    // Extract x-amz-meta-* headers as metadata
    const metadata: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      if (k.toLowerCase().startsWith("x-amz-meta-")) {
        metadata[k.slice("x-amz-meta-".length)] = v;
      }
    });
    return {
      contentType: res.headers.get("content-type") ?? undefined,
      contentLength: res.headers.get("content-length") ? Number(res.headers.get("content-length")) : undefined,
      etag: res.headers.get("etag") ?? undefined,
      lastModified: res.headers.get("last-modified") ?? undefined,
      metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
      versionId: res.headers.get("x-amz-version-id") ?? undefined,
      storageClass: res.headers.get("x-amz-storage-class") ?? undefined,
    };
  },

  setAcl: async (args: Value[]) => {
    const bucket = args[0] as string;
    const key = args[1] as string;
    const acl = args[2] as string;
    const options = (args[3] as Record<string, unknown>) ?? {};
    const config = getConfig(options.profile as string);
    await s3Fetch({
      method: "PUT",
      path: pathForBucketKey(bucket, key),
      query: { acl: "" },
      headers: {
        "x-amz-acl": acl,
      },
      body: "",
      config,
    });
    return { success: true, bucket, key, acl };
  },
};

export const S3FunctionMetadata = {
  configure: {
    description: "Configure S3 client credentials and endpoint",
    parameters: [
      {
        name: "options",
        dataType: "object",
        required: true,
        description: "Configuration: region, endpoint, accessKeyId, secretAccessKey, sessionToken, forcePathStyle, profile",
      },
    ],
    returns: { type: "object", description: "{ success, profile }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  upload: {
    description: "Upload an object to S3",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "key", dataType: "string", formInputType: "text", required: true, description: "Object key" },
      { name: "body", dataType: "string | Buffer", required: true, description: "Object content" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: contentType, metadata, profile" },
    ],
    returns: { type: "object", description: "{ etag, versionId }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  download: {
    description: "Download an object from S3",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "key", dataType: "string", formInputType: "text", required: true, description: "Object key" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: encoding, profile" },
    ],

    returnType: "object",
    returnDescription: "API response.",
  },
  remove: {
    description: "Delete an object from S3",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "key", dataType: "string", formInputType: "text", required: true, description: "Object key" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],
    returns: { type: "object", description: "{ success, bucket, key }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  list: {
    description: "List objects in an S3 bucket",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: prefix, delimiter, maxKeys, continuationToken, profile" },
    ],
    returns: { type: "object", description: "{ contents[], commonPrefixes[], isTruncated, nextContinuationToken }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  exists: {
    description: "Check if an object exists in S3",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "key", dataType: "string", formInputType: "text", required: true, description: "Object key" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],

    returnType: "object",
    returnDescription: "API response.",
  },
  copy: {
    description: "Copy an object within or between S3 buckets",
    parameters: [
      { name: "sourceBucket", dataType: "string", formInputType: "text", required: true, description: "Source bucket name" },
      { name: "sourceKey", dataType: "string", formInputType: "text", required: true, description: "Source object key" },
      { name: "destBucket", dataType: "string", formInputType: "text", required: true, description: "Destination bucket name" },
      { name: "destKey", dataType: "string", formInputType: "text", required: true, description: "Destination object key" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],
    returns: { type: "object", description: "{ etag, lastModified }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  move: {
    description: "Move an object (copy then delete source)",
    parameters: [
      { name: "sourceBucket", dataType: "string", formInputType: "text", required: true, description: "Source bucket name" },
      { name: "sourceKey", dataType: "string", formInputType: "text", required: true, description: "Source object key" },
      { name: "destBucket", dataType: "string", formInputType: "text", required: true, description: "Destination bucket name" },
      { name: "destKey", dataType: "string", formInputType: "text", required: true, description: "Destination object key" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],
    returns: { type: "object", description: "{ success, from, to }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  presignUrl: {
    description: "Generate a presigned URL for an S3 object",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "key", dataType: "string", formInputType: "text", required: true, description: "Object key" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: expiresIn (seconds, default 3600), method (GET/PUT), contentType, profile" },
    ],
    returns: { type: "object", description: "{ url, expiresIn }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  createBucket: {
    description: "Create a new S3 bucket",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],
    returns: { type: "object", description: "{ success, bucket }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  deleteBucket: {
    description: "Delete an S3 bucket",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],
    returns: { type: "object", description: "{ success, bucket }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  listBuckets: {
    description: "List all S3 buckets",
    parameters: [
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],
    returns: { type: "object[]", description: "Array of { name, creationDate }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  getMetadata: {
    description: "Get metadata for an S3 object",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "key", dataType: "string", formInputType: "text", required: true, description: "Object key" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],
    returns: { type: "object", description: "{ contentType, contentLength, etag, lastModified, metadata, versionId, storageClass }" },
    returnType: "object",
    returnDescription: "API response.",
  },
  setAcl: {
    description: "Set the ACL for an S3 object",
    parameters: [
      { name: "bucket", dataType: "string", formInputType: "text", required: true, description: "Bucket name" },
      { name: "key", dataType: "string", formInputType: "text", required: true, description: "Object key" },
      { name: "acl", dataType: "string", formInputType: "text", required: true, description: "ACL value: private, public-read, public-read-write, authenticated-read" },
      { name: "options", dataType: "object", formInputType: "json", required: false, description: "Options: profile" },
    ],
    returns: { type: "object", description: "{ success, bucket, key, acl }" },
    returnType: "object",
    returnDescription: "API response.",
  },
};

export const S3ModuleMetadata = {
  description: "S3-compatible object storage operations using AWS Signature V4 over HTTPS",
  version: "1.0.0",
  dependencies: [],
};
