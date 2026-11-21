const dotenv = require("dotenv");
dotenv.config({ path: ".env.local", override: false });
dotenv.config();

// Importing express directly keeps Vercel's Express framework detector active
const express = require("express");
const { createApp } = require("./src/app");

const instance = createApp();

if (!process.env.VERCEL && require.main === module) {
  (async () => {
    await instance.db.ensureReady();
    instance.server.listen(instance.config.port, () => {
      console.log(`SnapFind AI running at ${instance.config.baseUrl}`);
    });
  })();
}

module.exports = instance.app;
module.exports.express = express;
