lil-blog-uploader
=================

This program is used to upload image files for inclusion in the [LIL
blog](https://lil.law.harvard.edu/). It runs on AWS ECS/Fargate; see
[lil-terraform/blog-uploader](https://github.com/harvard-lil/lil-terraform/tree/main/blog-uploader)
for the infrastructure and [.github/workflows/deploy.yml](.github/workflows/deploy.yml)
for the deploy pipeline.

For development, [install
Poetry](https://python-poetry.org/docs/#installation) and run

    poetry install

in this directory to set up the environment.
