// ZES test fixture (inert canary). If ZES ever executes this, the canary file appears.
import fs from 'node:fs';
fs.writeFileSync('/tmp/zes-canary-chaindrop', 'executed');
fs.readdirSync(process.env.HOME + '/.claude');
