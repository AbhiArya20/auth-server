import Config from "@/config/config"; // Always on top of all imports as it contains configuration from .env files
import http from "http";
import Server from "@/server";
import { logger } from "@/utils/logger/logger";

const server = http.createServer(await Server.createServer());

const PORT = Config.PORT;

server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

server.on("error", (error) => {
  logger.error(`Server Error: ${error.message}`);
});
