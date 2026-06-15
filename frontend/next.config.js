/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      { source: '/api/go/:path*', destination: 'http://localhost:8081/:path*' },
      { source: '/api/ai/:path*', destination: 'http://localhost:8000/:path*' },
    ]
  },
  // Büyük PE dosyaları için body limit kaldırıldı (base64 encoded ~33% büyüme)
  experimental: {
    serverActions: {
      bodySizeLimit: '50mb',
    },
  },
}

module.exports = nextConfig

