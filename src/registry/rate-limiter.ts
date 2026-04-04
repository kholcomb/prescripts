import pLimit from "p-limit";

let limiter = pLimit(5);

export function setRegistryConcurrency(n: number): void {
  limiter = pLimit(n);
}

export function withLimit<T>(fn: () => Promise<T>): Promise<T> {
  return limiter(fn);
}
