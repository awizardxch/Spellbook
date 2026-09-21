"use client";

import { useCallback, useEffect, useState } from "react";

/** String state persisted to localStorage. SSR-safe (hydrates on mount). */
export function useLocalStorage(key: string, initial: string): [string, (v: string) => void] {
  const [val, setVal] = useState(initial);
  useEffect(() => {
    try {
      const s = window.localStorage.getItem(key);
      if (s !== null) setVal(s);
    } catch {
      /* storage unavailable */
    }
  }, [key]);
  const set = useCallback(
    (v: string) => {
      setVal(v);
      try {
        window.localStorage.setItem(key, v);
      } catch {
        /* storage unavailable */
      }
    },
    [key]
  );
  return [val, set];
}

/** JSON state persisted to localStorage. SSR-safe (hydrates on mount). */
export function useLocalStorageJson<T>(key: string, initial: T): [T, (v: T) => void] {
  const [val, setVal] = useState<T>(initial);
  useEffect(() => {
    try {
      const s = window.localStorage.getItem(key);
      if (s !== null) setVal(JSON.parse(s) as T);
    } catch {
      /* storage unavailable or corrupt */
    }
  }, [key]);
  const set = useCallback(
    (v: T) => {
      setVal(v);
      try {
        window.localStorage.setItem(key, JSON.stringify(v));
      } catch {
        /* storage unavailable */
      }
    },
    [key]
  );
  return [val, set];
}
