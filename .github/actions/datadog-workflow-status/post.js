const core = require("@actions/core");

async function run() {
  try {
    const startTime = Number(core.getState("startTime"));
    const endTime = Math.floor(Date.now() / 1000);

    const duration = endTime - startTime;

    const status = process.env.STATE_jobStatus || process.env.JOB_STATUS || "unknown";

    const apiKey = core.getInput("datadog-api-key");

    const payload = {
      series: [
        {
          metric: "github.actions.workflow.duration",
          type: "gauge",
          points: [[endTime, duration]],
          tags: [
            `repo:${process.env.GITHUB_REPOSITORY}`,
            `workflow:${process.env.GITHUB_WORKFLOW}`,
            `branch:${process.env.GITHUB_REF_NAME}`,
            `status:${status}`
          ]
        }
      ]
    };

    console.log(JSON.stringify(payload, null, 2));

    const response = await fetch(
      "https://api.datadoghq.com/api/v1/series",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "DD-API-KEY": apiKey
        },
        body: JSON.stringify(payload)
      }
    );

    if (!response.ok) {
      const text = await response.text();
      core.setFailed(`Datadog API failed: ${text}`);
    }

    console.log("Metrics sent");
  } catch (err) {
    core.setFailed(err.message);
  }
}

run();