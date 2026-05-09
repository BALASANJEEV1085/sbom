import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Lock monorepo Turbopack to this app so routes in ./app are always used. */
const appRoot = path.dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  turbopack: {
    root: appRoot,
  },
};

export default nextConfig;
