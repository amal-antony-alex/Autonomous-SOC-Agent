
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const configDir = dirname(fileURLToPath(import.meta.url))
const projectRoot = resolve(configDir, '..')

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, projectRoot, '')

  const addReviewerToken = (proxy) => {
    proxy.on('proxyReq', (proxyReq) => {
      const token = env.SOC_REVIEWER_TOKEN

      if (token) {
        proxyReq.setHeader('Authorization', `Bearer ${token}`)
      }
    })
  }

  return {
    plugins: [
      react(),
      tailwindcss(),
    ],
    server: {
      proxy: {
        '/api/v1/response-actions': {
          target: 'http://localhost:8000',
          changeOrigin: true,
          configure: addReviewerToken,
        },
        '/api/v1/dashboard': {
          target: 'http://localhost:8000',
          changeOrigin: true,
          configure: addReviewerToken,
        },
        '/api/v1/alerts': {
          target: 'http://localhost:8000',
          changeOrigin: true,
          configure: addReviewerToken,
        },
        '/api/v1/incidents': {
          target: 'http://localhost:8000',
          changeOrigin: true,
          configure: addReviewerToken,
        },
        '/api/v1/investigations': {
          target: 'http://localhost:8000',
          changeOrigin: true,
          configure: addReviewerToken,
        },
      },
    },
  }
})
