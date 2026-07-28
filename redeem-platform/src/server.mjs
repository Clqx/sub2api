import http from 'node:http'
import { loadConfig } from './config.mjs'
import { RedeemDatabase } from './database.mjs'
import { createHTTPHandler } from './http-app.mjs'
import { RedemptionService } from './redemption-service.mjs'
import { DemoSub2APIClient, Sub2APIClient } from './sub2api-client.mjs'

const config = loadConfig()
const database = new RedeemDatabase(config.databasePath, config.migrationDir)
const sub2api = config.demoMode
  ? new DemoSub2APIClient()
  : new Sub2APIClient(config)
const service = new RedemptionService({ database, sub2api, config })
const handler = createHTTPHandler({ config, database, service, sub2api })
const server = http.createServer(handler)

service.startRetryWorker()

server.listen(config.port, config.host, () => {
  console.info(JSON.stringify({
    event: 'redeem_platform_started',
    host: config.host,
    port: config.port,
    demo_mode: config.demoMode,
  }))
})

function shutdown(signal) {
  console.info(JSON.stringify({ event: 'redeem_platform_stopping', signal }))
  service.stopRetryWorker()
  server.close(() => {
    database.close()
    process.exit(0)
  })
  setTimeout(() => process.exit(1), 10000).unref()
}

process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
