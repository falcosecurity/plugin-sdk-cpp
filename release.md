# Release Process

Our release process is fully automated using [Github actions](.github/workflows/release.yaml).

When we release we do the following process:

1. We decide together (usually in the #falco channel in [slack](https://kubernetes.slack.com/messages/falco)) what's the next version to tag
2. Make sure that Makefile `FALCOSECURITY_LIBS_REVISION` points to an actual libs tag, since the release workflow will use the value as a badge
3. A person with repository rights creates the Github Release with empty release notes
4. The automated release workflow will start and generate the release notes

> __NOTE:__ Since the release workflow uses [rn2md](https://github.com/leodido/rn2md) tool to generate release notes, make sure to always set correct `release-note` info in the PR body!
