import './config'          // validate env vars before anything else
import app from './app'
import { config } from './config'

app.listen(config.PORT, () => {
  console.log(`effata-api listening on port ${config.PORT}`)
})
