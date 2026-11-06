export const PUBLIC_LIMITS = Object.freeze({
  requestBytes: 16 * 1024,
  responseBytes: 64 * 1024,
  bodyTimeoutMs: 2_000,
  urlCharacters: 2_048,
  futureDefaultPageSize: 10,
  futureMaxPageSize: 25,
});

export class RequestLimitError extends Error {
  readonly status: 400 | 408 | 413;
  readonly code: string;

  constructor(status: 400 | 408 | 413, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

/** Byte cap applies to streamed bytes even when Content-Length is missing or false. */
export async function consumeBoundedBody(
  request: Request,
  maxBytes = PUBLIC_LIMITS.requestBytes,
  timeoutMs = PUBLIC_LIMITS.bodyTimeoutMs,
): Promise<void> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || !Number.isSafeInteger(Number(declared)))) {
    throw new RequestLimitError(400, "invalid_content_length");
  }
  if (declared !== null && Number(declared) > maxBytes) {
    throw new RequestLimitError(413, "request_too_large");
  }
  if (request.body === null) return;

  const reader = request.body.getReader();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let bytes = 0;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new RequestLimitError(408, "request_body_timeout")), timeoutMs);
  });
  try {
    while (true) {
      const chunk = await Promise.race([reader.read(), deadline]);
      if (chunk.done) return;
      bytes += chunk.value.byteLength;
      if (bytes > maxBytes) throw new RequestLimitError(413, "request_too_large");
    }
  } catch (error) {
    // Cancellation must not keep a timed-out or hostile stream alive.
    void reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    reader.releaseLock();
  }
}
