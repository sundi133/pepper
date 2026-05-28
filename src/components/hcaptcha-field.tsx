"use client";

import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";

declare global {
  interface Window {
    hcaptcha?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      reset: (id?: string) => void;
      remove: (id: string) => void;
    };
  }
}

const SCRIPT_ID = "hcaptcha-api-script";
const SCRIPT_SRC = "https://js.hcaptcha.com/1/api.js?render=explicit";

export type HcaptchaFieldHandle = { reset: () => void };

type Props = {
  siteKey: string;
  onVerify: (token: string) => void;
  onExpire?: () => void;
};

export const HcaptchaField = forwardRef<HcaptchaFieldHandle, Props>(
  function HcaptchaField({ siteKey, onVerify, onExpire }, ref) {
    const containerRef = useRef<HTMLDivElement>(null);
    const widgetIdRef = useRef<string | null>(null);
    const [ready, setReady] = useState(false);

    // Keep latest callbacks in refs so the rendered widget never calls a stale closure.
    const onVerifyRef = useRef(onVerify);
    const onExpireRef = useRef(onExpire);
    useEffect(() => {
      onVerifyRef.current = onVerify;
      onExpireRef.current = onExpire;
    });

    useImperativeHandle(ref, () => ({
      reset() {
        if (widgetIdRef.current !== null && window.hcaptcha) {
          window.hcaptcha.reset(widgetIdRef.current);
        }
      },
    }));

    // Load the hCaptcha API script once.
    useEffect(() => {
      let cancelled = false;
      const markReady = () => {
        if (!cancelled) setReady(true);
      };

      if (window.hcaptcha) {
        const t = setTimeout(markReady, 0);
        return () => {
          cancelled = true;
          clearTimeout(t);
        };
      }

      const existing = document.getElementById(SCRIPT_ID);
      if (existing) {
        const poll = setInterval(() => {
          if (window.hcaptcha) {
            markReady();
            clearInterval(poll);
          }
        }, 200);
        return () => {
          cancelled = true;
          clearInterval(poll);
        };
      }

      const script = document.createElement("script");
      script.id = SCRIPT_ID;
      script.src = SCRIPT_SRC;
      script.async = true;
      script.defer = true;
      script.onload = markReady;
      document.head.appendChild(script);
      return () => {
        cancelled = true;
      };
    }, []);

    // Render the widget once the API is ready (guard against double render).
    useEffect(() => {
      if (!ready || !containerRef.current || !window.hcaptcha) return;
      if (widgetIdRef.current !== null) return;
      widgetIdRef.current = window.hcaptcha.render(containerRef.current, {
        sitekey: siteKey,
        callback: (token: string) => onVerifyRef.current(token),
        "expired-callback": () => onExpireRef.current?.(),
        "error-callback": () => onExpireRef.current?.(),
      });
    }, [ready, siteKey]);

    return <div ref={containerRef} className="flex justify-center" />;
  },
);
