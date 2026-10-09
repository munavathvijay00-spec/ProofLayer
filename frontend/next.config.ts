import type {NextConfig} from 'next';
const backend=(process.env.BACKEND_URL||'http://127.0.0.1:8000').replace(/\/$/,'');
const nextConfig:NextConfig={output:'standalone',experimental:{cpus:1},async rewrites(){return [{source:'/backend/:path*',destination:backend+'/:path*'}]}};
export default nextConfig;
