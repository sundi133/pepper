import { useId, type SVGProps } from "react";

/**
 * Brand logos for scan sources.
 *
 * GitHub, Bitbucket and Subversion: SVG Logos by Gil Barbara (CC0-1.0),
 * https://github.com/gilbarbara/logos. Azure DevOps: Devicon (MIT),
 * https://github.com/devicons/devicon. GitHub uses currentColor so it stays
 * visible in dark mode; the others keep their brand colors.
 */

type LogoProps = SVGProps<SVGSVGElement>;

export function GithubLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 256 250" fill="currentColor" aria-hidden {...props}>
      <path d="M128.001 0C57.317 0 0 57.307 0 128.001c0 56.554 36.676 104.535 87.535 121.46c6.397 1.185 8.746-2.777 8.746-6.158c0-3.052-.12-13.135-.174-23.83c-35.61 7.742-43.124-15.103-43.124-15.103c-5.823-14.795-14.213-18.73-14.213-18.73c-11.613-7.944.876-7.78.876-7.78c12.853.902 19.621 13.19 19.621 13.19c11.417 19.568 29.945 13.911 37.249 10.64c1.149-8.272 4.466-13.92 8.127-17.116c-28.431-3.236-58.318-14.212-58.318-63.258c0-13.975 5-25.394 13.188-34.358c-1.329-3.224-5.71-16.242 1.24-33.874c0 0 10.749-3.44 35.21 13.121c10.21-2.836 21.16-4.258 32.038-4.307c10.878.049 21.837 1.47 32.066 4.307c24.431-16.56 35.165-13.12 35.165-13.12c6.967 17.63 2.584 30.65 1.255 33.873c8.207 8.964 13.173 20.383 13.173 34.358c0 49.163-29.944 59.988-58.447 63.157c4.591 3.972 8.682 11.762 8.682 23.704c0 17.126-.148 30.91-.148 35.126c0 3.407 2.304 7.398 8.792 6.14C219.37 232.5 256 184.537 256 128.002C256 57.307 198.691 0 128.001 0" />
    </svg>
  );
}

export function BitbucketLogo(props: LogoProps) {
  const id = useId();
  return (
    <svg viewBox="0 0 256 231" aria-hidden {...props}>
      <defs>
        <linearGradient id={id} x1="108.633%" x2="46.927%" y1="13.818%" y2="78.776%">
          <stop offset="18%" stopColor="#0052cc" />
          <stop offset="100%" stopColor="#2684ff" />
        </linearGradient>
      </defs>
      <g fill="none">
        <path
          fill="#2684ff"
          d="M8.308 0A8.202 8.202 0 0 0 .106 9.516l34.819 211.373a11.155 11.155 0 0 0 10.909 9.31h167.04a8.2 8.2 0 0 0 8.201-6.89l34.82-213.752a8.202 8.202 0 0 0-8.203-9.514zm146.616 152.768h-53.315l-14.436-75.42h80.67z"
        />
        <path
          fill={`url(#${id})`}
          d="M244.61 77.242h-76.916l-12.909 75.36h-53.272l-62.902 74.663a11.1 11.1 0 0 0 7.171 2.704H212.73a8.196 8.196 0 0 0 8.196-6.884z"
        />
      </g>
    </svg>
  );
}

export function AzureDevOpsLogo(props: LogoProps) {
  const id = useId();
  return (
    <svg viewBox="0 0 128 128" aria-hidden {...props}>
      <defs>
        <linearGradient
          id={id}
          x1="9"
          x2="9"
          y1="16.97"
          y2="1.03"
          gradientTransform="scale(7.11111)"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0" stopColor="#0078d4" />
          <stop offset=".16" stopColor="#1380da" />
          <stop offset=".53" stopColor="#3c91e5" />
          <stop offset=".82" stopColor="#559cec" />
          <stop offset="1" stopColor="#5ea0ef" />
        </linearGradient>
      </defs>
      <path
        fill={`url(#${id})`}
        d="M120.89 28.445v69.262l-28.445 23.324l-44.09-16.07v15.93L23.395 88.25l72.746 5.688V31.574ZM96.64 31.93L55.82 7.11v16.285L18.348 34.418L7.109 48.852v32.785l16.075 7.11V46.718Zm0 0"
      />
    </svg>
  );
}

export function SubversionLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 256 186" aria-hidden {...props}>
      <path
        fill="#809cc8"
        d="M0 0v67.149c34.6-14.407 80.831-28.887 139.01-43.497C176.29 14.304 212.32 6.444 247.12 0zm256 14.318c-33.737 5.014-63.992 10.914-90.62 17.58c-30.482 7.657-55.022 15.397-73.582 23.29c-18.584 7.75-27.217 14.019-26.008 18.848c1.09 4.264 8.873 6.2 23.38 5.8c7.466-.142 19.556-.963 36.338-2.447s38.45-3.63 64.974-6.434c26.291-2.714 48.068-4.55 65.518-5.618zM181.058 99.5c-7.467.094-17.746.665-30.902 1.631c-13.202.99-29.536 2.415-49.115 4.44c-30.388 3.252-55.681 5.782-75.758 7.431c-9.63.813-17.998 1.318-25.283 1.722v54.463c39.875-5.83 75.947-12.779 108.109-20.843c31.597-7.916 55.882-15.64 72.949-23.108c17.09-7.468 25.07-13.804 23.742-18.94c-1.114-4.428-9.117-6.678-23.742-6.796M256 118.62c-35.04 13.727-78.53 27.19-130.492 40.236C77.13 170.986 35.341 179.665 0 185.045v.453h256z"
      />
    </svg>
  );
}
