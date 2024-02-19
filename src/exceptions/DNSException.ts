export default class DNSException extends Error {
  constructor(
    message?: string,
    public readonly type = 'unknown',
    public readonly cause?: unknown
  ) {
    super(message);
  }
}
