module.exports = {
  testEnvironment: "node",
  transform: {
    "^.+\\.(ts|js)$": ["ts-jest", { isolatedModules: true }],
  },
  transformIgnorePatterns: ["node_modules/(?!@stablelib)"],
};
