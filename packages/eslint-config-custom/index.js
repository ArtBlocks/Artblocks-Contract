module.exports = {
  env: { "shared-node-browser": true, es6: true },
  extends: ["eslint:recommended", "plugin:prettier/recommended"],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaFeatures: { jsx: true },
    ecmaVersion: 2018,
    sourceType: "module",
  },
  root: true,
  rules: {
    "no-var": "error",
    "brace-style": "error",
    "prefer-template": "error",
    radix: "error",
    "space-before-blocks": "error",
    "import/prefer-default-export": "off",
  },
};
