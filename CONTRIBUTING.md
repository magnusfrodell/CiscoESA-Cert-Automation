# Guidance on how to contribute

Contributions to this code are welcome and appreciated.
Please adhere to our [Code of Conduct](./CODE_OF_CONDUCT.md) at all times.

> All contributions to this code will be released under the terms of the [LICENSE](./LICENSE) of this code. By submitting a pull request or filing a bug, issue, or feature request, you are agreeing to comply with this waiver of copyright interest. Details can be found in our [LICENSE](./LICENSE).

There are two primary ways to contribute:

1. Using the issue tracker
2. Changing the codebase


## Using the issue tracker

Use the issue tracker to suggest feature requests, report bugs, and ask questions. This is also a great way to connect with the developers of the project as well as others who are interested in this solution.

Use the issue tracker to find ways to contribute. Find a bug or a feature, mention in the issue that you will take on that effort, then follow the _Changing the codebase_ guidance below.

When reporting a problem with the appliance dialogue, please attach the output of a run with `-v --transcript <file>` (passwords are redacted automatically) and state the AsyncOS version (`version` in the CLI) and whether the appliance is clustered.


## Changing the codebase

Generally speaking, you should fork this repository, make changes in your own fork, and then submit a pull request. All new code should have associated unit tests (if applicable) that validate implemented features and the presence or lack of defects.

Additionally, the code should follow any stylistic and architectural guidelines prescribed by the project. In the absence of such guidelines, mimic the styles and patterns in the existing codebase.

For this project specifically:

- Keep `esa_deploy.py` a single, dependency-light file (standard library plus `pexpect`, `tomli` only on Python < 3.11) so that it can be dropped onto any certbot host.
- Run the test suite before submitting: `python3 -m pytest -q`. The tests drive the real dialogue against `tests/fake_esa.py`, so new prompts or menu paths should be added there as scenario flags together with a test.
- Never log or print secrets. Anything that reaches the log or the transcript passes through `SecretRedactor`; keep it that way.
