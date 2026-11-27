// Conventional Commits, enforced in CI (.github/workflows/ci.yml) and locally by
// .githooks/commit-msg. release-plz turns them into the changelog and next version:
// fix: → patch, feat: → minor, feat!: or "BREAKING CHANGE:" → major.
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // Bodies carry explanations and trailers (Co-Authored-By); don't wrap-police them.
    'body-max-line-length': [0],
    'footer-max-line-length': [0],
  },
};
