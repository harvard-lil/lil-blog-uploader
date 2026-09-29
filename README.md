lil-blog-uploader
=================

This program is used to upload image files for inclusion in the [LIL
blog](https://lil.law.harvard.edu/). It runs on AWS ECS/Fargate behind a
Cloudflare Tunnel; see
[lil-terraform/blog-uploader](https://github.com/harvard-lil/lil-terraform/tree/main/blog-uploader)
for the infrastructure and [.github/workflows/deploy.yml](.github/workflows/deploy.yml)
for the deploy pipeline.

Cloudflare Access decides who may use it: any LIL Keycloak account. Access
forwards each request with a signed identity token (`Cf-Access-Jwt-Assertion`),
which the app verifies against the Access application's audience tag
(`ACCESS_AUD`) before serving anything but `/health`. Uploads are recorded in
the log with the uploader's email address.

Files go to the `lil-blog-media` S3 bucket under their own name, or with a
random suffix if that name is taken; S3 refuses any upload that would replace
an existing object. The task's IAM role supplies the AWS credentials.

For development, [install uv](https://docs.astral.sh/uv/getting-started/installation/)
and run the tests and linter:

    uv run pytest
    uv run ruff check .

With no Access in front of it, run the app in debug mode and name a stand-in
user:

    DEV_USER_EMAIL=you@law.harvard.edu FLASK_SECRET_KEY=dev S3_BUCKET=... \
      uv run flask --app app --debug run

Dependencies are declared in `pyproject.toml` and locked in `uv.lock`;
`uv lock --upgrade` refreshes them. The image installs exactly the locked set
(`uv sync --locked --no-dev`) on Python 3.14.
