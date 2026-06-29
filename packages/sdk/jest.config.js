/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["<rootDir>/tests/**/*.test.ts"],
  moduleNameMapper: {
    // Strip .js extensions so ts-jest resolves .ts source files at test time
    "^(\\.{1,2}/.*)\\.js$": "$1",
    "^@lupid/sdk$": "<rootDir>/src/index.ts",
  },
  collectCoverageFrom: ["src/**/*.ts"],
  coverageThreshold: {
    global: { branches: 70, functions: 80, lines: 80, statements: 80 },
  },
};
