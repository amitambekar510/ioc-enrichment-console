/** @type {import('next').NextConfig} */
const nextConfig = {
  // API calls go directly to the Flask backend (http://127.0.0.1:5000)
  // via NEXT_PUBLIC_BACKEND_URL env var — no rewrites needed.
  // This avoids Next.js 15 rewrite body-forwarding issues with POST requests.
};

module.exports = nextConfig;
