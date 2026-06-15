/** @type {import('next').NextConfig} */
const nextConfig = {
  // Standalone output for Docker (smaller image, node server.js)
  output: 'standalone',

  async rewrites() {
    // Docker: servis adları üzerinden iletişim
    // Standalone: localhost üzerinden (start.sh ile çalışırken)
    const goServerUrl = process.env.GO_SERVER_URL || 'http://sentinel-server:8081'
    const aiServerUrl = process.env.AI_SERVER_URL || 'http://sentinel-ai:8000'
    return [
      { source: '/api/go/:path*', destination: `${goServerUrl}/:path*` },
      { source: '/api/ai/:path*', destination: `${aiServerUrl}/:path*` },
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
