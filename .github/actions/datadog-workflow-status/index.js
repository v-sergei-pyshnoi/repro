const core = require("@actions/core");

async function run() {
  const startTime = Math.floor(Date.now() / 1000);

  core.saveState("startTime", startTime);

  console.log(`Start time: ${startTime}`);
}

run();